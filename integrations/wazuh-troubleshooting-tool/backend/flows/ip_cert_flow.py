from executor import run_command
from utils.fix_engine import FixEngine


def ip_cert_flow(user_choice=None, context=None):

    if context is None:
        context = {}

    response = {
        "display": "",
        "ask":     [],
        "done":    False,
        "context": context,
    }

    # -------------------------------------------------------------------------
    # ENTRY — explain and ask how to check IP
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_check":

        response["display"] = (
            "Since this is an existing installation, the initialization "
            "error is unexpected. Let's go through this step by step.\n\n"
            "First, let's check the IP address.\n\n"
            "The IP in config.yml should match the network.host value "
            "in /etc/wazuh-indexer/opensearch.yml.\n\n"
            "Would you like me to check it for you, "
            "or will you check it yourself?"
        )
        response["ask"]  = ["Check IP? (auto / manual)"]
        context["stage"] = "ip_check_choice"
        return response

    # -------------------------------------------------------------------------
    # IP CHECK CHOICE
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_check_choice":

        if user_choice and "auto" in user_choice.lower():
            context["stage"] = "ip_auto_check"
            return ip_cert_flow(context=context)  # silent routing — no display to lose

        # manual — give instructions and ask result
        response["display"] = (
            "Please check the following:\n\n"
            "  1. The IP in your config.yml "
            "(inside wazuh-install-files.tar → indexer section)\n"
            "  2. network.host in /etc/wazuh-indexer/opensearch.yml\n\n"
            "Both values should be the same.\n\n"
            "Is the IP correct?"
        )
        response["ask"]  = ["IP correct? (correct / not correct)"]
        context["stage"] = "ip_manual_result"
        return response

    # -------------------------------------------------------------------------
    # IP AUTO CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_auto_check":

        control = FixEngine.get_control_ip()
        indexer = FixEngine.get_indexer_ip()

        c_ip = FixEngine.extract_ip(control)
        i_ip = FixEngine.extract_ip(indexer)

        context["c_ip"] = c_ip
        context["i_ip"] = i_ip

        response["display"] = (
            f"IP Check result:\n"
            f"  config.yml IP:                {c_ip}\n"
            f"  opensearch.yml network.host:  {i_ip}"
        )

        if c_ip and i_ip and c_ip == i_ip:
            response["display"] += "\n\n[OK] IP addresses match.\n\n"
            response["ask"]  = ["IP is correct. Shall we move to cert path check? (yes)"]
            context["stage"] = "cert_path_check"
            return response  # FIX: was return ip_cert_flow() — user must see this first

        response["display"] += (
            "\n\n[ERROR] IP mismatch detected.\n\n"
            f"  config.yml says:     {c_ip}\n"
            f"  opensearch.yml has:  {i_ip}\n\n"
            "The opensearch.yml network.host should match config.yml.\n\n"
            "Would you like me to fix it, or will you fix it yourself?"
        )
        response["ask"]  = ["Fix IP? (fix / manual)"]
        context["stage"] = "ip_mismatch_fix"
        return response

    # -------------------------------------------------------------------------
    # IP MANUAL RESULT
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_manual_result":

        if user_choice and "not correct" in user_choice.lower():
            response["display"] = (
                "The IP needs to be corrected.\n\n"
                "Would you like me to fix it, or will you fix it yourself?"
            )
            response["ask"]  = ["Fix IP? (fix / manual)"]
            context["stage"] = "ip_mismatch_fix"
            return response

        # IP is correct — route to cert_path_check (it is auto, safe to recurse
        # because cert_path_check now correctly returns response without chaining)
        response["display"] = (
            "[OK] IP is correct.\n\n"
            "Moving on to check the certificate paths."
        )
        context["stage"] = "cert_path_check"
        return ip_cert_flow(context=context)  # safe: cert_path_check no longer auto-chains

    # -------------------------------------------------------------------------
    # IP MISMATCH FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_mismatch_fix":

        if user_choice and "fix" in user_choice.lower():

            c_ip = context.get("c_ip", "")
            if not c_ip:
                c_ip = FixEngine.extract_ip(FixEngine.get_control_ip()) or ""
                context["c_ip"] = c_ip

            run_command(
                f"sed -i 's/^network.host:.*/network.host: {c_ip}/' "
                "/etc/wazuh-indexer/opensearch.yml"
            )
            run_command("systemctl restart wazuh-indexer")

            response["display"] = (
                f"[OK] Updated network.host to {c_ip} in opensearch.yml.\n"
                "Restarted wazuh-indexer.\n\n"
                "Is the dashboard issue resolved now?"
            )
            response["ask"]  = ["Resolved? (resolved / not resolved)"]
            context["stage"] = "ip_post_auto_fix"
            return response

        # manual fix
        c_ip = context.get("c_ip", "<config.yml IP>")
        response["display"] = (
            f"Please edit /etc/wazuh-indexer/opensearch.yml and set:\n\n"
            f"  network.host: {c_ip}\n\n"
            "Then restart:\n"
            "  systemctl restart wazuh-indexer\n\n"
            "Let me know when you are done."
        )
        response["ask"]  = ["Done? (done)"]
        context["stage"] = "ip_post_manual_fix"
        return response

    # -------------------------------------------------------------------------
    # IP POST AUTO FIX — ask if resolved
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_post_auto_fix":

        if user_choice and "resolved" in user_choice.lower():
            response["display"] = "Great! The issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "Still not resolved. "
            "Let me check the IP address once more to confirm..."
        )
        context["stage"] = "ip_recheck"
        return ip_cert_flow(context=context)  # safe: ip_recheck builds its own display

    # -------------------------------------------------------------------------
    # IP POST MANUAL FIX — ask if resolved
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_post_manual_fix":

        response["display"] = "Is the dashboard issue resolved now?"
        response["ask"]  = ["Resolved? (resolved / not resolved)"]
        context["stage"] = "ip_post_manual_resolved"
        return response

    # -------------------------------------------------------------------------
    # IP POST MANUAL RESOLVED
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_post_manual_resolved":

        if user_choice and "resolved" in user_choice.lower():
            response["display"] = "Great! The issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "Still not resolved. "
            "Let me check the IP address once more to confirm..."
        )
        context["stage"] = "ip_recheck"
        return ip_cert_flow(context=context)  # safe: ip_recheck builds its own display

    # -------------------------------------------------------------------------
    # IP RECHECK — verify and force fix if still wrong
    # -------------------------------------------------------------------------
    if context.get("stage") == "ip_recheck":

        control = FixEngine.get_control_ip()
        indexer = FixEngine.get_indexer_ip()

        c_ip = FixEngine.extract_ip(control)
        i_ip = FixEngine.extract_ip(indexer)

        context["c_ip"] = c_ip
        context["i_ip"] = i_ip

        response["display"] = (
            f"IP recheck:\n"
            f"  config.yml IP:                {c_ip}\n"
            f"  opensearch.yml network.host:  {i_ip}"
        )

        if c_ip and i_ip and c_ip == i_ip:
            response["display"] += (
                "\n\n[OK] IP is correct.\n\n"
                "Moving on to check the certificate paths."
            )
            context["stage"] = "cert_path_check"
            return ip_cert_flow(context=context)  # safe: cert_path_check no longer auto-chains

        # still wrong — fix automatically and move on
        run_command(
            f"sed -i 's/^network.host:.*/network.host: {c_ip}/' "
            "/etc/wazuh-indexer/opensearch.yml"
        )
        run_command("systemctl restart wazuh-indexer")

        response["display"] += (
            f"\n\n[ERROR] IP was still incorrect.\n"
            f"  Fixed network.host to {c_ip} and restarted wazuh-indexer.\n\n"
            "Moving on to check the certificate paths."
        )
        context["stage"] = "cert_path_check"
        return ip_cert_flow(context=context)  # safe: cert_path_check no longer auto-chains

    # -------------------------------------------------------------------------
    # CERT PATH CHECK — auto compare, tell user result
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_path_check":

        paths_raw = run_command(
            "grep -E 'pemkey_filepath|pemcert_filepath|pemtrustedcas_filepath' "
            "/etc/wazuh-indexer/opensearch.yml"
        ) or ""

        files_raw = run_command(
            "ls /etc/wazuh-indexer/certs"
        ) or ""

        # extract filenames from configured paths
        configured = []
        for line in paths_raw.splitlines():
            if ":" in line:
                val = line.split(":", 1)[1].strip()
                configured.append(val.split("/")[-1])  # just the filename

        # extract actual filenames
        actual = [f.strip() for f in files_raw.splitlines() if f.strip()]

        missing = [f for f in configured if f not in actual]

        context["cert_missing"]    = missing
        context["cert_paths_raw"]  = paths_raw
        context["cert_files_raw"]  = files_raw

        response["display"] = (
            "Let's check the certificate paths.\n\n"
            "Configured cert paths\n"
            "(from /etc/wazuh-indexer/opensearch.yml):\n"
            f"{paths_raw}\n\n"
            "Available cert files\n"
            "(in /etc/wazuh-indexer/certs/):\n"
            f"{files_raw}\n\n"
        )

        if not missing:
            response["display"] += "[OK] All configured cert paths match the actual files.\n\n"
            response["ask"]  = ["Cert paths OK. Shall we check permissions? (yes)"]
            context["stage"] = "cert_perm_check"
            return response  # FIX: was return ip_cert_flow() — user must see cert path result first

        response["display"] += (
            "[ERROR] The following configured cert files were not found "
            "in /etc/wazuh-indexer/certs/:\n"
            + "\n".join(f"  - {f}" for f in missing)
            + "\n\nShould I fix the paths in opensearch.yml to match "
            "the actual files, or will you fix it yourself?"
        )
        response["ask"]  = ["Fix cert paths? (auto / manual)"]
        context["stage"] = "cert_path_fix"
        return response

    # -------------------------------------------------------------------------
    # CERT PATH FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_path_fix":

        if user_choice and "auto" in user_choice.lower():

            actual_files = run_command(
                "ls /etc/wazuh-indexer/certs"
            ) or ""
            actual = [f.strip() for f in actual_files.splitlines() if f.strip()]

            # build correct paths
            key  = next((f for f in actual if "key" in f and "admin" not in f), None)
            cert = next((f for f in actual if "key" not in f and "root" not in f
                         and "admin" not in f), None)
            ca   = next((f for f in actual if "root-ca" in f), None)

            if key and cert and ca:
                base = "/etc/wazuh-indexer/certs"
                cmds = [
                    f"sed -i 's|pemcert_filepath:.*|pemcert_filepath: {base}/{cert}|g' "
                    "/etc/wazuh-indexer/opensearch.yml",
                    f"sed -i 's|pemkey_filepath:.*|pemkey_filepath: {base}/{key}|g' "
                    "/etc/wazuh-indexer/opensearch.yml",
                    f"sed -i 's|pemtrustedcas_filepath:.*|pemtrustedcas_filepath: {base}/{ca}|g' "
                    "/etc/wazuh-indexer/opensearch.yml",
                    "systemctl restart wazuh-indexer",
                ]
                for cmd in cmds:
                    run_command(cmd)

                response["display"] = (
                    f"[OK] Updated cert paths in opensearch.yml:\n\n"
                    f"  cert:  {base}/{cert}\n"
                    f"  key:   {base}/{key}\n"
                    f"  CA:    {base}/{ca}\n\n"
                    "Restarted wazuh-indexer.\n\n"
                    "Shall we move on to check permissions?"
                )
                response["ask"]  = ["Check permissions? (yes)"]
                context["stage"] = "cert_perm_check"
                return response  # FIX: was return ip_cert_flow() — display was being lost

            else:
                response["display"] = (
                    "[ERROR] Could not automatically identify cert files.\n"
                    "Please fix manually:\n\n"
                    "  /etc/wazuh-indexer/opensearch.yml\n\n"
                    "Let me know when done."
                )
                response["ask"]  = ["Done? (done)"]
                context["stage"] = "cert_path_wait"
                return response

        else:
            response["display"] = (
                "Please update the cert paths in:\n"
                "  /etc/wazuh-indexer/opensearch.yml\n\n"
                "Keys to fix:\n"
                "  plugins.security.ssl.transport.pemkey_filepath\n"
                "  plugins.security.ssl.transport.pemcert_filepath\n"
                "  plugins.security.ssl.transport.pemtrustedcas_filepath\n"
                "  plugins.security.ssl.http.pemkey_filepath\n"
                "  plugins.security.ssl.http.pemcert_filepath\n"
                "  plugins.security.ssl.http.pemtrustedcas_filepath\n\n"
                "Match them to the files in /etc/wazuh-indexer/certs/\n\n"
                "Let me know when done."
            )
            response["ask"]  = ["Done? (done)"]
            context["stage"] = "cert_path_wait"
            return response

    # -------------------------------------------------------------------------
    # CERT PATH WAIT
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_path_wait":

        response["display"] = (
            "Paths updated.\n\n"
            "Shall we check the permissions?"
        )
        response["ask"]  = ["Check permissions? (yes)"]
        context["stage"] = "cert_perm_check"
        return response  # FIX: was return ip_cert_flow() — display was being lost

    # -------------------------------------------------------------------------
    # CERT PERMISSION CHECK — auto analyse, no yes/no from user
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_perm_check":

        dir_perms  = run_command("ls -ld /etc/wazuh-indexer/certs") or ""
        file_perms = run_command("ls -l /etc/wazuh-indexer/certs")  or ""

        # --- analyse directory ---
        dir_ok    = False
        dir_line  = dir_perms.strip()
        if dir_line:
            parts     = dir_line.split()
            dir_mode  = parts[0] if len(parts) > 0 else ""
            dir_owner = parts[2] if len(parts) > 2 else ""
            dir_ok    = (dir_mode == "dr-x------" and dir_owner == "wazuh-indexer")

        # --- analyse files (skip the "total N" header line) ---
        file_issues = []
        for line in file_perms.splitlines():
            line = line.strip()
            if not line or line.startswith("total"):
                continue
            parts      = line.split()
            file_mode  = parts[0] if len(parts) > 0 else ""
            file_owner = parts[2] if len(parts) > 2 else ""
            filename   = parts[-1] if parts else "?"
            if file_mode != "-r--------" or file_owner != "wazuh-indexer":
                file_issues.append(
                    f"  {filename}  →  mode={file_mode}  owner={file_owner}"
                )

        all_ok = dir_ok and not file_issues

        response["display"] = (
            "Checking certificate permissions...\n\n"
            f"Directory:\n{dir_perms}\n\n"
            f"Files:\n{file_perms}\n\n"
            "Expected:\n"
            "  Directory: dr-x------ (500) owned by wazuh-indexer\n"
            "  Files:     -r-------- (400) owned by wazuh-indexer\n\n"
        )

        if all_ok:
            response["display"] += (
                "[OK] All indexer permissions are correct.\n\n"
                "All indexer IP and certificate checks passed.\n\n"
                "Now let's check the dashboard configuration."
            )
            response["ask"]  = ["Move to dashboard checks? (yes)"]
            context["stage"] = "dash_ip_check"
            return response

        # build a clear error summary
        issues_lines = ""
        if not dir_ok:
            issues_lines += (
                f"  Directory: mode={dir_mode}  owner={dir_owner}"
                "  (expected dr-x------ wazuh-indexer)\n"
            )
        if file_issues:
            issues_lines += "  Files with wrong permissions:\n"
            issues_lines += "\n".join(file_issues) + "\n"

        response["display"] += (
            "[ERROR] Permission issues found:\n\n"
            + issues_lines
            + "\nShould I fix them for you, or will you do it yourself?"
        )
        response["ask"]  = ["Fix permissions? (auto / manual)"]
        context["stage"] = "cert_perm_apply"
        return response

    # -------------------------------------------------------------------------
    # APPLY CERT PERMISSION FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_perm_apply":

        if user_choice and "auto" in user_choice.lower():
            cmds = [
                "chmod 500 /etc/wazuh-indexer/certs",
                "chmod 400 /etc/wazuh-indexer/certs/*",
                "chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs",
                "systemctl restart wazuh-indexer",
            ]
            for cmd in cmds:
                run_command(cmd)

            dir_perms  = run_command("ls -ld /etc/wazuh-indexer/certs") or ""
            file_perms = run_command("ls -l /etc/wazuh-indexer/certs")  or ""

            response["display"] = (
                "Permissions fixed and wazuh-indexer restarted.\n\n"
                f"Directory:\n{dir_perms}\n\n"
                f"Files:\n{file_perms}\n\n"
                "Is the issue now resolved?"
            )

        else:
            response["display"] = (
                "Run these commands manually:\n\n"
                "  chmod 500 /etc/wazuh-indexer/certs\n"
                "  chmod 400 /etc/wazuh-indexer/certs/*\n"
                "  chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs\n"
                "  systemctl restart wazuh-indexer\n\n"
                "Let me know when done."
            )
            response["ask"]  = ["Done? (done)"]
            context["stage"] = "cert_perm_final"
            return response

        response["ask"]  = ["Resolved? (resolved / not resolved)"]
        context["stage"] = "cert_perm_final"
        return response

    # -------------------------------------------------------------------------
    # FINAL CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "cert_perm_final":

        choice = (user_choice or "").lower()

        if "resolved" in choice or "done" in choice:
            response["display"] = "Great! The issue is resolved."
            response["done"]    = True
        else:
            response["display"] = (
                "Still persists. Passing to log analysis for deeper investigation."
            )
            context["stage"] = "fetch_logs"

        return response
