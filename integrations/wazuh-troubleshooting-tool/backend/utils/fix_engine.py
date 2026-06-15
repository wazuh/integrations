from executor import run_command
from config import KIBANA_USERNAME, INDEXER_URL

import re
import secrets
import string


class FixEngine:

    # -----------------------------------------
    # GET IP FROM config.yml (control file)
    # -----------------------------------------
    @staticmethod
    def get_control_ip():
        output = run_command(
            "tar -axf /home/vagrant/wazuh-install-files.tar "
            "wazuh-install-files/config.yml -O"
        ) or ""

        in_indexer = False

        for line in output.splitlines():
            if "indexer:" in line:
                in_indexer = True
                continue
            if in_indexer and line.strip().endswith(":") and "ip:" not in line:
                in_indexer = False
            if in_indexer and "ip:" in line:
                return line.strip()

        return ""

    # -----------------------------------------
    # GET IP FROM INDEXER CONFIG
    # -----------------------------------------
    @staticmethod
    def get_indexer_ip():
        return run_command(
            "grep network.host /etc/wazuh-indexer/opensearch.yml"
        ) or ""

    # -----------------------------------------
    # GET IP FROM DASHBOARD CONFIG
    # -----------------------------------------
    @staticmethod
    def get_dashboard_ip():
        return run_command(
            "grep opensearch.hosts /etc/wazuh-dashboard/opensearch_dashboards.yml"
        ) or ""

    # -----------------------------------------
    # EXTRACT IP (helper)
    # -----------------------------------------
    @staticmethod
    def extract_ip(text):
        if not text:
            return None
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
        return match.group(1) if match else None

    # -----------------------------------------
    # COMPARE IPS
    # -----------------------------------------
    @staticmethod
    def compare_ips():
        control   = FixEngine.get_control_ip()
        indexer   = FixEngine.get_indexer_ip()
        dashboard = FixEngine.get_dashboard_ip()

        c_ip = FixEngine.extract_ip(control)
        i_ip = FixEngine.extract_ip(indexer)
        d_ip = FixEngine.extract_ip(dashboard)

        return {
            "control":   c_ip,
            "indexer":   i_ip,
            "dashboard": d_ip,
            "match":     (c_ip == i_ip == d_ip),
        }
    # -----------------------------------------
    # FULL IP CHECK
    # -----------------------------------------
    @staticmethod
    def check_ips():

        data = FixEngine.compare_ips()

        result = (
            f"Control IP:   {data['control']}\n"
            f"Indexer IP:   {data['indexer']}\n"
            f"Dashboard IP: {data['dashboard']}"
        )

        if not data["match"]:
            result += "\n\n[ERROR] IP mismatch detected."
        else:
            result += "\n\n[OK] IP configuration looks correct."

        return result
    # -----------------------------------------
    # GET CERT PATHS FROM DASHBOARD CONFIG
    # -----------------------------------------
    @staticmethod
    def get_cert_paths():
        return run_command(
            "grep -E 'certificate|key|ca' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        ) or ""

    # -----------------------------------------
    # LIST CERT FILES
    # -----------------------------------------
    @staticmethod
    def list_cert_files():
        return run_command("ls -lrt /etc/wazuh-dashboard/certs") or ""
    # -----------------------------------------
    # CHECK CERT PERMISSIONS
    # -----------------------------------------
    @staticmethod
    def check_cert_permissions():

        perms = run_command(
            "ls -ld /etc/wazuh-dashboard/certs"
        ) or ""

        files = run_command(
            "ls -l /etc/wazuh-dashboard/certs"
        ) or ""

        return (
            f"Directory permissions:\n{perms}\n\n"
            f"Certificate files:\n{files}"
        )

        # -----------------------------------------
    # CHECK CERT PATHS
    # -----------------------------------------
    @staticmethod
    def check_cert_paths():

        paths = FixEngine.get_cert_paths()
        files = FixEngine.list_cert_files()

        return (
            f"Configured cert paths:\n{paths}\n\n"
            f"Available cert files:\n{files}"
        )
    # -----------------------------------------
    # FIX CERT PERMISSIONS
    # -----------------------------------------
    @staticmethod
    def fix_cert_permissions():
        cmds = [
            "chmod 500 /etc/wazuh-dashboard/certs",
            "chmod 400 /etc/wazuh-dashboard/certs/*",
            "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs",
        ]
        output = ""
        for cmd in cmds:
            output += (run_command(cmd) or "") + "\n"
        return output

    # -----------------------------------------
    # RESTART INDEXER  (Bug fixed: out was undefined)
    # -----------------------------------------
    @staticmethod
    def restart_indexer():
        out    = run_command("systemctl restart wazuh-indexer") or ""
        status = run_command("systemctl is-active wazuh-indexer") or ""
        return f"Restart output:\n{out}\nStatus after restart: {status}"

    # -----------------------------------------
    # DASHBOARD STATUS
    # -----------------------------------------
    @staticmethod
    def status_dashboard():
        return run_command("systemctl is-active wazuh-dashboard") or "unknown"


    # -----------------------------------------
    # DASHBOARD STATUS
    # -----------------------------------------
    @staticmethod
    def status_indexer():
        return run_command("systemctl is-active wazuh-indexer") or "unknown"
    # -----------------------------------------
    # CONNECTIVITY CHECK
    # -----------------------------------------
    @staticmethod
    def check_connectivity(password):
        cmd = (
            f"curl -XGET -k -u {KIBANA_USERNAME}:{password} "
            f"{INDEXER_URL}/_cluster/health"
        )
        return run_command(cmd) or ""

    # -----------------------------------------
    # GENERATE NEW PASSWORD
    # -----------------------------------------
    @staticmethod
    def generate_password(length=16):
        chars = string.ascii_letters + string.digits + ".*+?-"
        return ''.join(secrets.choice(chars) for _ in range(length))

    # -----------------------------------------
    # APPLY NEW PASSWORD (INDEXER + DASHBOARD)
    # -----------------------------------------
    @staticmethod
    def apply_new_password(password):
        cmd1 = (
            "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
            f"wazuh-passwords-tool.sh -u kibanaserver -p '{password}'"
        )
        cmd2 = (
            f"echo {password} | "
            "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore "
            "--allow-root add -f --stdin opensearch.password"
        )
        out1 = run_command(cmd1) or ""
        out2 = run_command(cmd2) or ""
        return f"{out1}\n{out2}"

    # -----------------------------------------
    # VERIFY PASSWORD
    # -----------------------------------------
    @staticmethod
    def verify_password(password):
        cmd = (
            f"curl -s -k -u {KIBANA_USERNAME}:{password} "
            f"{INDEXER_URL}"
        )
        return run_command(cmd) or ""

    # -----------------------------------------
    # HEAP FIX STEPS (manual instructions)
    # -----------------------------------------
    @staticmethod
    def heap_steps():
        return (
            "Edit file:\n"
            "  /etc/wazuh-indexer/jvm.options\n\n"
            "Set heap to 50% of your RAM.\n"
            "Example for 8 GB system:\n"
            "  -Xms4g\n"
            "  -Xmx4g\n\n"
            "Then restart:\n"
            "  systemctl restart wazuh-indexer"
        )
        # -------------------------------------------------------------------------
    # FIX JVM HEAP
    # -------------------------------------------------------------------------
    @staticmethod
    def fix_jvm_heap(heap_gb):

        run_command(
            f"sed -i 's/^-Xms.*/-Xms{heap_gb}g/' "
            "/etc/wazuh-indexer/jvm.options"
        )

        run_command(
            f"sed -i 's/^-Xmx.*/-Xmx{heap_gb}g/' "
            "/etc/wazuh-indexer/jvm.options"
        )

        run_command(
            "systemctl restart wazuh-indexer"
        )

        updated = run_command(
            "grep -E '^-Xms|^-Xmx' "
            "/etc/wazuh-indexer/jvm.options"
        ) or "(could not read)"

        return updated
    # -----------------------------------------
    # SECURITY INIT COMMAND
    # -----------------------------------------
    @staticmethod
    def init_command():
        return (
            "/usr/share/wazuh-indexer/bin/indexer-security-init.sh"
        )

    # -----------------------------------------
    # PERMISSION FIX STEPS (manual instructions)
    # -----------------------------------------
    @staticmethod
    def permission_fix():
        return (
            "Run the following commands:\n"
            "  chmod 600 /usr/share/wazuh-indexer/config/jvm.options\n"
            "  chmod 600 /usr/share/wazuh-indexer/config/opensearch.yml\n"
            "  chmod 600 /usr/share/wazuh-indexer/config/opensearch-security/*.yml\n\n"
            "Then restart:\n"
            "  systemctl restart wazuh-indexer"
        )

    # -----------------------------------------
    # DISK CHECK
    # -----------------------------------------
    @staticmethod
    def check_disk():
        return run_command("df -h") or ""

    # -----------------------------------------
    # MANUAL COMMAND SETS  (for "give me commands" path)
    # -----------------------------------------
    @staticmethod
    def commands_ip_fix(c_ip):
        return (
            f"sed -i 's|https://.*:9200|https://{c_ip}:9200|' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml\n"
            "systemctl restart wazuh-dashboard"
        )

    @staticmethod
    def commands_cert_permissions():
        return (
            "chmod 500 /etc/wazuh-dashboard/certs\n"
            "chmod 400 /etc/wazuh-dashboard/certs/*\n"
            "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs\n"
            "systemctl restart wazuh-dashboard"
        )

    @staticmethod
    def commands_restart_indexer():
        return "systemctl restart wazuh-indexer"

    @staticmethod
    def commands_get_indexer_logs():
        return (
            "journalctl -u wazuh-indexer --since '1 hour ago' "
            "| grep -i -E 'error|warn'"
        )
