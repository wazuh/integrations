from executor import run_command
from config import KIBANA_USERNAME, INDEXER_URL
from utils.cache_utils import cached
from utils.archive_utils import extract_from_archive
from utils.service_utils import restart_service_and_wait, get_service_status

import re
import secrets
import string


class FixEngine:

    # -----------------------------------------
    # GET IP FROM config.yml (control file)
    # -----------------------------------------
    @staticmethod
    def get_control_ip():

        # Cached (utils/cache_utils.py): avoid re-reading this on every
        # single troubleshooting step within the same session. The read
        # itself uses utils/archive_utils.py, which copies the archive to
        # local disk once before extracting — much faster than extracting
        # directly from /home/vagrant if that's a slow shared folder.
        output = cached(
            "control_ip_raw",
            lambda: extract_from_archive(
                "/home/vagrant/wazuh-install-files.tar",
                "wazuh-install-files/config.yml",
            ),
        )

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
        status = restart_service_and_wait("wazuh-indexer")
        return f"Status after restart: {status}"

    # -----------------------------------------
    # RESTART INDEXER AND WAIT FOR ACTIVE STATE
    # Returns the final status string ("active", "failed", "activating", etc.)
    #
    # Delegates to utils/service_utils.py, which uses "--no-block" so the
    # restart command returns immediately instead of blocking indefinitely
    # while a slow-starting service (e.g. JVM-based wazuh-indexer) comes up,
    # then polls "is-active" itself with a bounded, predictable window.
    # -----------------------------------------
    @staticmethod
    def restart_indexer_and_wait(max_attempts=20, delay=3):
        return restart_service_and_wait("wazuh-indexer", max_attempts=max_attempts, delay=delay)

    # -----------------------------------------
    # DASHBOARD STATUS
    # -----------------------------------------
    @staticmethod
    def status_dashboard():
        return get_service_status("wazuh-dashboard") or "unknown"

    # -----------------------------------------
    # INDEXER STATUS
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
            f"printf '%s' '{password}' | "
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

        # Restart and actually wait for the service to come back up, the
        # same way fix_indexer_ip() and fix_indexer_cert_paths() do.
        # A bare run_command("systemctl restart ...") returns immediately
        # once the restart is *issued*, not once it's actually active, so
        # it can look like nothing happened if the service takes a moment
        # or fails to come back up.
        status = FixEngine.restart_indexer_and_wait()

        updated = run_command(
            "grep -E '^-Xms|^-Xmx' "
            "/etc/wazuh-indexer/jvm.options"
        ) or "(could not read)"

        return {"updated": updated, "status": status}

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

    # -----------------------------------------
    # CHECK INDEXER IP (control vs opensearch.yml)
    # -----------------------------------------
    @staticmethod
    def check_indexer_ip():
        control = FixEngine.get_control_ip()
        indexer = FixEngine.get_indexer_ip()

        c_ip = FixEngine.extract_ip(control)
        i_ip = FixEngine.extract_ip(indexer)

        return {
            "c_ip":  c_ip,
            "i_ip":  i_ip,
            "match": bool(c_ip and i_ip and c_ip == i_ip),
        }

    # -----------------------------------------
    # FIX INDEXER IP (auto correct) + restart, waits for active
    # -----------------------------------------
    @staticmethod
    def fix_indexer_ip(c_ip):
        run_command(
            f"sed -i 's/^network.host:.*/network.host: {c_ip}/' "
            "/etc/wazuh-indexer/opensearch.yml"
        )
        return FixEngine.restart_indexer_and_wait()

    # -----------------------------------------
    # CHECK INDEXER CERT PATHS
    # -----------------------------------------
    @staticmethod
    def check_indexer_cert_paths():
        paths_raw = run_command(
            "grep -E 'pemkey_filepath|pemcert_filepath|pemtrustedcas_filepath' "
            "/etc/wazuh-indexer/opensearch.yml"
        ) or ""

        files_raw = run_command("ls /etc/wazuh-indexer/certs") or ""

        configured = []
        for line in paths_raw.splitlines():
            if ":" in line:
                val = line.split(":", 1)[1].strip()
                configured.append(val.split("/")[-1])

        actual  = [f.strip() for f in files_raw.splitlines() if f.strip()]
        missing = [f for f in configured if f not in actual]

        return {
            "paths_raw": paths_raw,
            "files_raw": files_raw,
            "missing":   missing,
        }

    # -----------------------------------------
    # FIX INDEXER CERT PATHS (auto correct) + restart, waits for active
    # -----------------------------------------
    @staticmethod
    def fix_indexer_cert_paths():
        actual_files = run_command("ls /etc/wazuh-indexer/certs") or ""
        actual = [f.strip() for f in actual_files.splitlines() if f.strip()]

        key  = next((f for f in actual if "key" in f and "admin" not in f), None)
        cert = next((f for f in actual if "key" not in f and "root" not in f
                     and "admin" not in f), None)
        ca   = next((f for f in actual if "root-ca" in f), None)

        if not (key and cert and ca):
            return {"success": False}

        base = "/etc/wazuh-indexer/certs"
        cmds = [
            f"sed -i 's|pemcert_filepath:.*|pemcert_filepath: {base}/{cert}|g' "
            "/etc/wazuh-indexer/opensearch.yml",
            f"sed -i 's|pemkey_filepath:.*|pemkey_filepath: {base}/{key}|g' "
            "/etc/wazuh-indexer/opensearch.yml",
            f"sed -i 's|pemtrustedcas_filepath:.*|pemtrustedcas_filepath: {base}/{ca}|g' "
            "/etc/wazuh-indexer/opensearch.yml",
        ]
        for cmd in cmds:
            run_command(cmd)

        status = FixEngine.restart_indexer_and_wait()

        return {"success": True, "cert": cert, "key": key, "ca": ca, "status": status}

    # -----------------------------------------
    # CHECK JVM HEAP (current vs recommended)
    # -----------------------------------------
    @staticmethod
    def check_jvm_heap():
        current = run_command(
            "grep -E '^-Xms|^-Xmx' /etc/wazuh-indexer/jvm.options"
        ) or "(could not read)"

        total_kb = run_command(
            "grep MemTotal /proc/meminfo | awk '{print $2}'"
        ) or "0"

        try:
            total_gb = round(int(total_kb.strip()) / 1024 / 1024)
        except ValueError:
            total_gb = 0

        heap_gb = max(1, total_gb // 2)

        return {"current": current, "total_gb": total_gb, "recommended_heap": heap_gb}

    # -----------------------------------------
    # CHECK DASHBOARD IP
    # -----------------------------------------
    @staticmethod
    def check_dashboard_ip():
        dash_raw = FixEngine.get_dashboard_ip()
        control  = FixEngine.get_control_ip()

        d_ip = FixEngine.extract_ip(dash_raw)
        c_ip = FixEngine.extract_ip(control)

        return {
            "d_ip":  d_ip,
            "c_ip":  c_ip,
            "match": bool(d_ip and c_ip and d_ip == c_ip),
        }

    # -----------------------------------------
    # FIX DASHBOARD IP (auto correct) + restart, waits for active
    # -----------------------------------------
    @staticmethod
    def fix_dashboard_ip(c_ip):
        run_command(
            f"sed -i 's|https://.*:9200|https://{c_ip}:9200|' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        )
        return restart_service_and_wait("wazuh-dashboard")

    # -----------------------------------------
    # CHECK DASHBOARD CERT PATHS
    # -----------------------------------------
    @staticmethod
    def check_dashboard_cert_paths():
        paths_raw = run_command(
            "grep -E 'ssl.certificate|ssl.key|certificateAuthorities' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        ) or ""

        files_raw = run_command("ls /etc/wazuh-dashboard/certs") or ""

        configured = []
        for line in paths_raw.splitlines():
            if ":" in line:
                val = line.split(":", 1)[1].strip().strip('"').strip("'").strip("[]")
                val = val.strip('"').strip("'")
                filename = val.split("/")[-1]
                if filename:
                    configured.append(filename)

        actual  = [f.strip() for f in files_raw.splitlines() if f.strip()]
        missing = [f for f in configured if f not in actual]

        return {
            "paths_raw": paths_raw,
            "files_raw": files_raw,
            "missing":   missing,
        }

    # -----------------------------------------
    # FIX DASHBOARD CERT PATHS (auto correct) + restart, waits for active
    # -----------------------------------------
    @staticmethod
    def fix_dashboard_cert_paths():
        actual_files = run_command("ls /etc/wazuh-dashboard/certs") or ""
        actual = [f.strip() for f in actual_files.splitlines() if f.strip()]

        key  = next((f for f in actual if "key" in f and "admin" not in f), None)
        cert = next((f for f in actual if "key" not in f and "root" not in f
                     and "admin" not in f and "ca" not in f.lower()), None)
        ca   = next((f for f in actual if "root-ca" in f or
                     ("ca" in f.lower() and "key" not in f)), None)

        if not (key and cert and ca):
            return {"success": False}

        base = "/etc/wazuh-dashboard/certs"
        cmds = [
            f"sed -i 's|server.ssl.certificate:.*|server.ssl.certificate: {base}/{cert}|g' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml",
            f"sed -i 's|server.ssl.key:.*|server.ssl.key: {base}/{key}|g' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml",
            "sed -i 's|opensearch.ssl.certificateAuthorities:.*"
            f"|opensearch.ssl.certificateAuthorities: [\"{base}/{ca}\"]|g' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml",
        ]
        for cmd in cmds:
            run_command(cmd)

        status = restart_service_and_wait("wazuh-dashboard")

        return {"success": True, "cert": cert, "key": key, "ca": ca, "status": status}

    # -----------------------------------------
    # DASHBOARD CERT PATH MANUAL STEPS
    # -----------------------------------------
    @staticmethod
    def dashboard_cert_path_steps():
        return (
            "Update the cert paths in:\n"
            "  /etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
            "Keys to fix:\n"
            "  server.ssl.certificate\n"
            "  server.ssl.key\n"
            "  opensearch.ssl.certificateAuthorities\n\n"
            "Match them to the files in /etc/wazuh-dashboard/certs/"
        )
