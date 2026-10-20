"""
Wazuh certificate regeneration/redeploy.

Reusable by ANY troubleshooting flow that diagnoses a TLS/certificate error
(Filebeat output test, dashboard-not-ready, etc) instead of each flow
re-writing the same wazuh-certs-tool.sh + redeploy sequence by hand.

Node names (indexer/server/dashboard) are read from the original install
config (wazuh-install-files.tar/config.yml) the same way FixEngine.get_control_ip()
reads the indexer IP from it, so Auto mode doesn't need the user to supply
them - Manual mode still shows the underlying commands with the real names
filled in wherever we could resolve them.
"""

from executor import run_command
from utils.archive_utils import extract_from_archive
from utils.cache_utils import cached
from utils.service_utils import restart_service_and_wait

INSTALL_ARCHIVE = "/home/vagrant/wazuh-install-files.tar"
CONFIG_MEMBER = "wazuh-install-files/config.yml"
CERTS_TOOL_URL = "https://packages.wazuh.com/4.14/wazuh-certs-tool.sh"
WORKDIR = "/tmp/wazuh-certs-renew"
CERT_ARCHIVE = f"{WORKDIR}/wazuh-certificates.tar"


def _get_config_yml():
    return cached("install_config_yml_raw", lambda: extract_from_archive(INSTALL_ARCHIVE, CONFIG_MEMBER))


def get_node_name(section):
    """section: 'indexer' | 'server' | 'dashboard'. Returns that node's `name:` from config.yml."""
    in_section = False
    for line in _get_config_yml().splitlines():
        stripped = line.strip()
        if stripped == f"{section}:":
            in_section = True
            continue
        if in_section and stripped.startswith("name:"):
            return stripped.split(":", 1)[1].strip()
        if in_section and stripped.endswith(":") and not stripped.startswith("-"):
            in_section = False
    return ""


def get_node_names():
    return {
        "indexer": get_node_name("indexer"),
        "server": get_node_name("server"),
        "dashboard": get_node_name("dashboard"),
    }


def regenerate_and_redeploy_certs():
    """
    Regenerate certs with wazuh-certs-tool.sh and redeploy them to the
    Wazuh Indexer, Filebeat, and Dashboard on this host, then restart all
    three services. Returns a status dict.
    """
    names = get_node_names()
    n1, n2, n3 = names["indexer"], names["server"], names["dashboard"]

    log = []
    run_command(f"mkdir -p {WORKDIR}")
    log.append(run_command(f"cd {WORKDIR} && curl -sO {CERTS_TOOL_URL}") or "")
    log.append(run_command(f"cd {WORKDIR} && bash wazuh-certs-tool.sh -A") or "")

    # Wazuh Indexer
    log.append(run_command("rm -rf /etc/wazuh-indexer/certs && mkdir /etc/wazuh-indexer/certs") or "")
    log.append(run_command(
        f"tar -xf {CERT_ARCHIVE} -C /etc/wazuh-indexer/certs/ "
        f"./{n1}.pem ./{n1}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem"
    ) or "")
    run_command(f"mv -n /etc/wazuh-indexer/certs/{n1}.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem")
    run_command(f"mv -n /etc/wazuh-indexer/certs/{n1}-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem")
    run_command("chmod 500 /etc/wazuh-indexer/certs")
    run_command("chmod 400 /etc/wazuh-indexer/certs/*")
    run_command("chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs")

    # Filebeat
    log.append(run_command("rm -rf /etc/filebeat/certs && mkdir /etc/filebeat/certs") or "")
    log.append(run_command(
        f"tar -xf {CERT_ARCHIVE} -C /etc/filebeat/certs/ ./{n2}.pem ./{n2}-key.pem ./root-ca.pem"
    ) or "")
    run_command(f"mv -n /etc/filebeat/certs/{n2}.pem /etc/filebeat/certs/wazuh-server.pem")
    run_command(f"mv -n /etc/filebeat/certs/{n2}-key.pem /etc/filebeat/certs/wazuh-server-key.pem")
    run_command("chmod 500 /etc/filebeat/certs")
    run_command("chmod 400 /etc/filebeat/certs/*")
    run_command("chown -R root:root /etc/filebeat/certs")

    # Wazuh Dashboard
    log.append(run_command("rm -rf /etc/wazuh-dashboard/certs && mkdir /etc/wazuh-dashboard/certs") or "")
    log.append(run_command(
        f"tar -xf {CERT_ARCHIVE} -C /etc/wazuh-dashboard/certs/ ./{n3}.pem ./{n3}-key.pem ./root-ca.pem"
    ) or "")
    run_command(f"mv -n /etc/wazuh-dashboard/certs/{n3}.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem")
    run_command(f"mv -n /etc/wazuh-dashboard/certs/{n3}-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem")
    run_command("chmod 500 /etc/wazuh-dashboard/certs")
    run_command("chmod 400 /etc/wazuh-dashboard/certs/*")
    run_command("chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs")

    indexer_status = restart_service_and_wait("wazuh-indexer")
    filebeat_status = restart_service_and_wait("filebeat")
    dashboard_status = restart_service_and_wait("wazuh-dashboard")

    return {
        "ok": indexer_status == "active" and filebeat_status == "active" and dashboard_status == "active",
        "indexer_status": indexer_status,
        "filebeat_status": filebeat_status,
        "dashboard_status": dashboard_status,
        "log": "\n".join(l for l in log if l),
    }


def manual_cert_redeploy_instructions():
    names = get_node_names()
    n1 = names["indexer"] or "<WAZUH_INDEXER_NODE_NAME>"
    n2 = names["server"] or "<EXISTING_WAZUH_SERVER_NODE_NAME>"
    n3 = names["dashboard"] or "<WAZUH_DASHBOARD_NODE_NAME>"

    return (
        "Locate the config.yml file and run:\n\n"
        f"    curl -sO {CERTS_TOOL_URL}\n"
        "    bash wazuh-certs-tool.sh -A\n\n"
        "Set the node names (from config.yml):\n\n"
        f"    export NODE_NAME1={n1}\n"
        f"    export NODE_NAME2={n2}\n"
        f"    export NODE_NAME3={n3}\n\n"
        "Redeploy the certificates to the Wazuh Indexer:\n\n"
        "    rm -rf /etc/wazuh-indexer/certs\n"
        "    mkdir /etc/wazuh-indexer/certs\n"
        "    tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME1.pem ./$NODE_NAME1-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem\n"
        "    mv -n /etc/wazuh-indexer/certs/$NODE_NAME1.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem\n"
        "    mv -n /etc/wazuh-indexer/certs/$NODE_NAME1-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem\n"
        "    chmod 500 /etc/wazuh-indexer/certs\n"
        "    chmod 400 /etc/wazuh-indexer/certs/*\n"
        "    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs\n\n"
        "Redeploy the certificates to Filebeat:\n\n"
        "    rm -rf /etc/filebeat/certs\n"
        "    mkdir /etc/filebeat/certs\n"
        "    tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME2.pem ./$NODE_NAME2-key.pem ./root-ca.pem\n"
        "    mv -n /etc/filebeat/certs/$NODE_NAME2.pem /etc/filebeat/certs/wazuh-server.pem\n"
        "    mv -n /etc/filebeat/certs/$NODE_NAME2-key.pem /etc/filebeat/certs/wazuh-server-key.pem\n"
        "    chmod 500 /etc/filebeat/certs\n"
        "    chmod 400 /etc/filebeat/certs/*\n"
        "    chown -R root:root /etc/filebeat/certs\n\n"
        "Redeploy the certificates to the Wazuh Dashboard:\n\n"
        "    rm -rf /etc/wazuh-dashboard/certs\n"
        "    mkdir /etc/wazuh-dashboard/certs\n"
        "    tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME3.pem ./$NODE_NAME3-key.pem ./root-ca.pem\n"
        "    mv -n /etc/wazuh-dashboard/certs/$NODE_NAME3.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem\n"
        "    mv -n /etc/wazuh-dashboard/certs/$NODE_NAME3-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem\n"
        "    chmod 500 /etc/wazuh-dashboard/certs\n"
        "    chmod 400 /etc/wazuh-dashboard/certs/*\n"
        "    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs\n\n"
        "Then restart all the components:\n\n"
        "    systemctl restart wazuh-indexer filebeat wazuh-dashboard"
    )
