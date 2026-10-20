import re

from executor import run_command
from utils.service_utils import restart_service_and_wait

FILEBEAT_LOG_PATH = "/var/log/filebeat/filebeat"

# Wazuh only ships/supports this exact Filebeat build - see:
# https://documentation.wazuh.com/current/upgrade-guide/index.html#wazuh-components-compatibility
SUPPORTED_FILEBEAT_VERSION = "7.10.2"
FILEBEAT_DEB_URL = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-7.10.2-amd64.deb"
FILEBEAT_RPM_URL = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-7.10.2-x86_64.rpm"


def run_filebeat_output_test():
    """Run `filebeat test output` and judge OK/failed from the actual text, not just presence of the word OK."""
    out = run_command("filebeat test output") or ""
    upper = out.upper()
    ok = "OK" in upper and "ERROR" not in upper
    return {"raw": out, "ok": ok}


def get_filebeat_log_errors(lines=200):
    return run_command(f"tail -n {lines} {FILEBEAT_LOG_PATH} | grep -i -E 'error|warn'") or ""


def get_filebeat_version(test_raw=""):
    """Pull the version out of `filebeat test output`'s own report (e.g.
    'version: 7.10.2') if we already have it, else ask Filebeat directly."""
    match = re.search(r"version:\s*([\d.]+)", test_raw or "")
    if match:
        return match.group(1)
    out = run_command("filebeat version") or ""
    match = re.search(r"(\d+\.\d+\.\d+)", out)
    return match.group(1) if match else ""


def classify_filebeat_failure(test_raw, log_errors=""):
    """
    Best-effort classification of why `filebeat test output` failed, based on
    the actual text rather than a guess. Returns one of: "unsupported_version",
    "tls_cert_error", "auth_failure", "indexer_unreachable", "unknown".
    """
    text = f"{test_raw}\n{log_errors}".lower()

    if "invalid_index_name_exception" in text or "could not connect to a compatible version" in text:
        return "unsupported_version"
    if any(kw in text for kw in ["x509", "certificate", "tls", "ssl", "handshake"]):
        return "tls_cert_error"
    if any(kw in text for kw in ["unauthorized", "authentication", "401"]):
        return "auth_failure"
    if any(kw in text for kw in [
        "connection refused", "no route to host", "i/o timeout",
        "network is unreachable", "dial up... error", "talk to server... error",
    ]):
        return "indexer_unreachable"
    return "unknown"


def fix_unsupported_filebeat_version():
    """
    Wazuh only supports Filebeat-OSS 7.10.2. Deploys the Wazuh Filebeat
    module + alerts template (the documented fix for the version-mismatch
    error), and reinstalls Filebeat-OSS 7.10.2 itself if the version is
    still wrong afterwards. Returns what ran and the final state.
    """
    log = []
    log.append(run_command("systemctl stop filebeat") or "")
    log.append(run_command(
        "curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.5.tar.gz "
        "| tar -xvz -C /usr/share/filebeat/module"
    ) or "")
    log.append(run_command(
        "curl -so /etc/filebeat/wazuh-template.json "
        "https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json"
    ) or "")
    log.append(run_command("chmod go+r /etc/filebeat/wazuh-template.json") or "")

    status = restart_service_and_wait("filebeat")
    version = get_filebeat_version()

    if version != SUPPORTED_FILEBEAT_VERSION:
        if run_command("command -v dpkg") :
            log.append(run_command(f"curl -so /tmp/filebeat-oss.deb {FILEBEAT_DEB_URL}") or "")
            log.append(run_command("dpkg -i /tmp/filebeat-oss.deb") or "")
        elif run_command("command -v rpm"):
            log.append(run_command(f"curl -so /tmp/filebeat-oss.rpm {FILEBEAT_RPM_URL}") or "")
            log.append(run_command("rpm -Uvh /tmp/filebeat-oss.rpm") or "")
        status = restart_service_and_wait("filebeat")
        version = get_filebeat_version()

    return {
        "ok": version == SUPPORTED_FILEBEAT_VERSION,
        "version": version or "unknown",
        "status": status,
        "log": "\n".join(l for l in log if l),
    }


def manual_unsupported_version_instructions():
    return (
        f"Wazuh is only compatible with Filebeat-OSS {SUPPORTED_FILEBEAT_VERSION}. "
        "Manually upgrading to a newer version is not recommended - it can break "
        "alert forwarding and index integration.\n"
        "https://documentation.wazuh.com/current/upgrade-guide/index.html#wazuh-components-compatibility\n\n"
        "Stop Filebeat:\n\n"
        "    systemctl stop filebeat\n\n"
        "Download the Wazuh Filebeat module:\n\n"
        "    curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.5.tar.gz | sudo tar -xvz -C /usr/share/filebeat/module\n\n"
        "Download the alerts template:\n\n"
        "    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json\n"
        "    chmod go+r /etc/filebeat/wazuh-template.json\n\n"
        "Restart Filebeat, then check the version again:\n\n"
        "    filebeat version\n\n"
        f"It should report Filebeat-OSS {SUPPORTED_FILEBEAT_VERSION}. If it still doesn't, reinstall Filebeat "
        f"with the OSS {SUPPORTED_FILEBEAT_VERSION} package directly:\n\n"
        f"    curl -so /tmp/filebeat-oss.deb {FILEBEAT_DEB_URL}   # Debian/Ubuntu\n"
        "    dpkg -i /tmp/filebeat-oss.deb\n\n"
        f"    curl -so /tmp/filebeat-oss.rpm {FILEBEAT_RPM_URL}   # RHEL/CentOS\n"
        "    rpm -Uvh /tmp/filebeat-oss.rpm"
    )
