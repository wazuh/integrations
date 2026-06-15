from executor import run_command
from utils.fix_engine import FixEngine


def dashboard_ip_cert_flow(user_choice=None, context=None):

    if context is None:
        context = {}

    response = {
        "display": "",
        "ask":     [],
        "done":    False,
        "context": context,
    }

    # -------------------------------------------------------------------------
    # ENTRY — explain and ask how to check dashboard IP
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_check":

        response["display"] = (
            "Indexer checks passed. Now let's verify the dashboard configuration.\n\n"
            "First, let's confirm the dashboard is pointing to the correct indexer IP.\n\n"
            "The opensearch.hosts value in:\n"
            "  /etc/wazuh-dashboard/opensearch_dashboards.yml\n"
            "should match the verified indexer IP.\n\n"
            "Would you like me to check it, or will you check it yourself?"
        )
        response["ask"]  = ["Check dashboard IP? (auto / manual)"]
        context["stage"] = "dash_ip_check_choice"
        return response

    # -------------------------------------------------------------------------
    # DASH IP CHECK CHOICE
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_check_choice":

        if user_choice and "auto" in user_choice.lower():
            context["stage"] = "dash_ip_auto_check"
            return dashboard_ip_cert_flow(context=context)  # silent routing

        response["display"] = (
            "Please check:\n\n"
            "  opensearch.hosts in "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
            f"It should point to the indexer IP: {context.get('c_ip', '<indexer IP>')}\n\n"
            "Is it correct?"
        )
        response["ask"]  = ["Dashboard IP correct? (correct / not correct)"]
        context["stage"] = "dash_ip_manual_result"
        return response

    # -------------------------------------------------------------------------
    # DASH IP AUTO CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_auto_check":

        dash_raw = FixEngine.get_dashboard_ip()
        d_ip     = FixEngine.extract_ip(dash_raw)
        c_ip     = context.get("c_ip") or FixEngine.extract_ip(FixEngine.get_control_ip())

        context["d_ip"] = d_ip
        context["c_ip"] = c_ip

        response["display"] = (
            "Dashboard IP check:\n"
            f"  opensearch_dashboards.yml opensearch.hosts:  {d_ip}\n"
            f"  Expected (verified indexer IP):               {c_ip}"
        )

        if d_ip and c_ip and d_ip == c_ip:
            response["display"] += "\n\n[OK] Dashboard IP matches the indexer IP.\n\n"
            response["ask"]  = ["IP correct. Shall we check dashboard cert paths? (yes)"]
            context["stage"] = "dash_cert_path_check"
            return response

        response["display"] += (
            "\n\n[ERROR] IP mismatch detected.\n\n"
            f"  opensearch_dashboards.yml has:  {d_ip}\n"
            f"  Should be (indexer IP):          {c_ip}\n\n"
            "Would you like me to fix it, or will you fix it yourself?"
        )
        response["ask"]  = ["Fix dashboard IP? (fix / manual)"]
        context["stage"] = "dash_ip_mismatch_fix"
        return response

    # -------------------------------------------------------------------------
    # DASH IP MANUAL RESULT
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_manual_result":

        if user_choice and "not correct" in user_choice.lower():
            response["display"] = (
                "The dashboard IP needs to be corrected.\n\n"
                "Would you like me to fix it, or will you fix it yourself?"
            )
            response["ask"]  = ["Fix dashboard IP? (fix / manual)"]
            context["stage"] = "dash_ip_mismatch_fix"
            return response

        # IP is correct — safe to recurse, dash_cert_path_check returns properly
        response["display"] = "[OK] Dashboard IP is correct.\n\nMoving on to check cert paths."
        context["stage"]    = "dash_cert_path_check"
        return dashboard_ip_cert_flow(context=context)

    # -------------------------------------------------------------------------
    # DASH IP MISMATCH FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_mismatch_fix":

        c_ip = context.get("c_ip", "")
        if not c_ip:
            c_ip = FixEngine.extract_ip(FixEngine.get_control_ip()) or ""
            context["c_ip"] = c_ip

        if user_choice and "fix" in user_choice.lower():
            run_command(
                f"sed -i 's|https://.*:9200|https://{c_ip}:9200|' "
                "/etc/wazuh-dashboard/opensearch_dashboards.yml"
            )
            run_command("systemctl restart wazuh-dashboard")

            response["display"] = (
                f"[OK] Updated opensearch.hosts to https://{c_ip}:9200 "
                "in opensearch_dashboards.yml.\n"
                "Restarted wazuh-dashboard.\n\n"
                "Is the dashboard issue resolved now?"
            )
            response["ask"]  = ["Resolved? (resolved / not resolved)"]
            context["stage"] = "dash_ip_post_auto_fix"
            return response

        # manual fix
        response["display"] = (
            "Please edit /etc/wazuh-dashboard/opensearch_dashboards.yml and set:\n\n"
            f"  opensearch.hosts: [\"https://{c_ip}:9200\"]\n\n"
            "Then restart:\n"
            "  systemctl restart wazuh-dashboard\n\n"
            "Let me know when done."
        )
        response["ask"]  = ["Done? (done)"]
        context["stage"] = "dash_ip_post_manual_fix"
        return response

    # -------------------------------------------------------------------------
    # DASH IP POST AUTO FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_post_auto_fix":

        if user_choice and "resolved" in user_choice.lower():
            response["display"] = "Great! The issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "Still not resolved. "
            "Let me recheck the dashboard IP..."
        )
        context["stage"] = "dash_ip_recheck"
        return dashboard_ip_cert_flow(context=context)

    # -------------------------------------------------------------------------
    # DASH IP POST MANUAL FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_post_manual_fix":

        response["display"] = "Is the dashboard issue resolved now?"
        response["ask"]  = ["Resolved? (resolved / not resolved)"]
        context["stage"] = "dash_ip_post_manual_resolved"
        return response

    # -------------------------------------------------------------------------
    # DASH IP POST MANUAL RESOLVED
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_post_manual_resolved":

        if user_choice and "resolved" in user_choice.lower():
            response["display"] = "Great! The issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "Still not resolved. "
            "Let me recheck the dashboard IP..."
        )
        context["stage"] = "dash_ip_recheck"
        return dashboard_ip_cert_flow(context=context)

    # -------------------------------------------------------------------------
    # DASH IP RECHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_ip_recheck":

        dash_raw = FixEngine.get_dashboard_ip()
        d_ip     = FixEngine.extract_ip(dash_raw)
        c_ip     = context.get("c_ip") or FixEngine.extract_ip(FixEngine.get_control_ip())

        context["d_ip"] = d_ip

        response["display"] = (
            "Dashboard IP recheck:\n"
            f"  opensearch_dashboards.yml opensearch.hosts:  {d_ip}\n"
            f"  Expected (indexer IP):                        {c_ip}"
        )

        if d_ip and c_ip and d_ip == c_ip:
            response["display"] += (
                "\n\n[OK] Dashboard IP is correct.\n\n"
                "Moving on to check cert paths."
            )
            context["stage"] = "dash_cert_path_check"
            return dashboard_ip_cert_flow(context=context)

        # still wrong — fix automatically
        run_command(
            f"sed -i 's|https://.*:9200|https://{c_ip}:9200|' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        )
        run_command("systemctl restart wazuh-dashboard")

        response["display"] += (
            f"\n\n[ERROR] IP was still incorrect.\n"
            f"  Fixed opensearch.hosts to https://{c_ip}:9200 "
            "and restarted wazuh-dashboard.\n\n"
            "Moving on to check cert paths."
        )
        context["stage"] = "dash_cert_path_check"
        return dashboard_ip_cert_flow(context=context)

    # -------------------------------------------------------------------------
    # DASH CERT PATH CHECK — auto compare, show result
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_path_check":

        paths_raw = run_command(
            "grep -E 'ssl.certificate|ssl.key|certificateAuthorities' "
            "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        ) or ""

        files_raw = run_command(
            "ls /etc/wazuh-dashboard/certs"
        ) or ""

        # extract filenames from configured paths
        configured = []
        for line in paths_raw.splitlines():
            if ":" in line:
                val = line.split(":", 1)[1].strip().strip('"').strip("'").strip("[]")
                # handle array format: ["/path/to/ca.pem"]
                val = val.strip('"').strip("'")
                filename = val.split("/")[-1]
                if filename:
                    configured.append(filename)

        actual  = [f.strip() for f in files_raw.splitlines() if f.strip()]
        missing = [f for f in configured if f not in actual]

        context["dash_cert_missing"]    = missing
        context["dash_cert_paths_raw"]  = paths_raw
        context["dash_cert_files_raw"]  = files_raw

        response["display"] = (
            "Let's check the dashboard certificate paths.\n\n"
            "Configured cert paths\n"
            "(from /etc/wazuh-dashboard/opensearch_dashboards.yml):\n"
            f"{paths_raw}\n\n"
            "Available cert files\n"
            "(in /etc/wazuh-dashboard/certs/):\n"
            f"{files_raw}\n\n"
        )

        if not missing:
            response["display"] += "[OK] All configured cert paths match the actual files.\n\n"
            response["ask"]  = ["Cert paths OK. Shall we check permissions? (yes)"]
            context["stage"] = "dash_cert_perm_check"
            return response  # user must see this before moving on

        response["display"] += (
            "[ERROR] The following configured cert files were not found "
            "in /etc/wazuh-dashboard/certs/:\n"
            + "\n".join(f"  - {f}" for f in missing)
            + "\n\nShould I fix the paths in opensearch_dashboards.yml to match "
            "the actual files, or will you fix it yourself?"
        )
        response["ask"]  = ["Fix dashboard cert paths? (auto / manual)"]
        context["stage"] = "dash_cert_path_fix"
        return response

    # -------------------------------------------------------------------------
    # DASH CERT PATH FIX
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_path_fix":

        if user_choice and "auto" in user_choice.lower():

            actual_files = run_command("ls /etc/wazuh-dashboard/certs") or ""
            actual       = [f.strip() for f in actual_files.splitlines() if f.strip()]

            key  = next((f for f in actual if "key" in f and "admin" not in f), None)
            cert = next((f for f in actual if "key" not in f
                         and "root" not in f and "admin" not in f
                         and "ca" not in f.lower()), None)
            ca   = next((f for f in actual if "root-ca" in f or
                         ("ca" in f.lower() and "key" not in f)), None)

            if key and cert and ca:
                base = "/etc/wazuh-dashboard/certs"
                cmds = [
                    f"sed -i 's|server.ssl.certificate:.*"
                    f"|server.ssl.certificate: {base}/{cert}|g' "
                    "/etc/wazuh-dashboard/opensearch_dashboards.yml",

                    f"sed -i 's|server.ssl.key:.*"
                    f"|server.ssl.key: {base}/{key}|g' "
                    "/etc/wazuh-dashboard/opensearch_dashboards.yml",

                    f"sed -i 's|opensearch.ssl.certificateAuthorities:.*"
                    f"|opensearch.ssl.certificateAuthorities: [\"{base}/{ca}\"]|g' "
                    "/etc/wazuh-dashboard/opensearch_dashboards.yml",

                    "systemctl restart wazuh-dashboard",
                ]
                for cmd in cmds:
                    run_command(cmd)

                response["display"] = (
                    f"[OK] Updated cert paths in opensearch_dashboards.yml:\n\n"
                    f"  cert:  {base}/{cert}\n"
                    f"  key:   {base}/{key}\n"
                    f"  CA:    {base}/{ca}\n\n"
                    "Restarted wazuh-dashboard.\n\n"
                    "Shall we move on to check permissions?"
                )
                response["ask"]  = ["Check permissions? (yes)"]
                context["stage"] = "dash_cert_perm_check"
                return response  # user must see fix result before moving on

            else:
                response["display"] = (
                    "[ERROR] Could not automatically identify dashboard cert files.\n"
                    "Please fix manually:\n\n"
                    "  /etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
                    "Let me know when done."
                )
                response["ask"]  = ["Done? (done)"]
                context["stage"] = "dash_cert_path_wait"
                return response

        else:
            response["display"] = (
                "Please update the cert paths in:\n"
                "  /etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
                "Keys to fix:\n"
                "  server.ssl.certificate\n"
                "  server.ssl.key\n"
                "  opensearch.ssl.certificateAuthorities\n\n"
                "Match them to the files in /etc/wazuh-dashboard/certs/\n\n"
                "Let me know when done."
            )
            response["ask"]  = ["Done? (done)"]
            context["stage"] = "dash_cert_path_wait"
            return response

    # -------------------------------------------------------------------------
    # DASH CERT PATH WAIT
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_path_wait":

        response["display"] = (
            "Paths updated.\n\n"
            "Shall we check the permissions?"
        )
        response["ask"]  = ["Check permissions? (yes)"]
        context["stage"] = "dash_cert_perm_check"
        return response  # user must see this before moving on

    # -------------------------------------------------------------------------
    # DASH CERT PERMISSION CHECK — auto analyse
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_perm_check":

        dir_perms  = run_command("ls -ld /etc/wazuh-dashboard/certs") or ""
        file_perms = run_command("ls -l /etc/wazuh-dashboard/certs")  or ""

        # analyse directory
        dir_ok   = False
        dir_line = dir_perms.strip()
        if dir_line:
            parts     = dir_line.split()
            dir_mode  = parts[0] if len(parts) > 0 else ""
            dir_owner = parts[2] if len(parts) > 2 else ""
            dir_ok    = (dir_mode == "dr-x------" and dir_owner == "wazuh-dashboard")

        # analyse files
        file_issues = []
        for line in file_perms.splitlines():
            line = line.strip()
            if not line or line.startswith("total"):
                continue
            parts      = line.split()
            file_mode  = parts[0] if len(parts) > 0 else ""
            file_owner = parts[2] if len(parts) > 2 else ""
            filename   = parts[-1] if parts else "?"
            if file_mode != "-r--------" or file_owner != "wazuh-dashboard":
                file_issues.append(
                    f"  {filename}  →  mode={file_mode}  owner={file_owner}"
                )

        all_ok = dir_ok and not file_issues

        response["display"] = (
            "Checking dashboard certificate permissions...\n\n"
            f"Directory:\n{dir_perms}\n\n"
            f"Files:\n{file_perms}\n\n"
            "Expected:\n"
            "  Directory: dr-x------ (500) owned by wazuh-dashboard\n"
            "  Files:     -r-------- (400) owned by wazuh-dashboard\n\n"
        )

        if all_ok:
            response["display"] += (
                "[OK] All dashboard permissions are correct.\n\n"
                "All dashboard IP and certificate checks passed.\n\n"
                "Now let's check the dashboard service status and logs."
            )
            response["ask"]  = ["Check dashboard status? (yes)"]
            context["stage"] = "dashboard_status_logs"
            return response  # dashboard_error_flow handles dashboard_status

        # build error summary
        issues_lines = ""
        if not dir_ok:
            issues_lines += (
                f"  Directory: mode={dir_mode}  owner={dir_owner}"
                "  (expected dr-x------ wazuh-dashboard)\n"
            )
        if file_issues:
            issues_lines += "  Files with wrong permissions:\n"
            issues_lines += "\n".join(file_issues) + "\n"

        response["display"] += (
            "[ERROR] Permission issues found:\n\n"
            + issues_lines
            + "\nShould I fix them for you, or will you do it yourself?"
        )
        response["ask"]  = ["Fix dashboard permissions? (auto / manual)"]
        context["stage"] = "dash_cert_perm_apply"
        return response

    # -------------------------------------------------------------------------
    # DASH CERT PERMISSION APPLY
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_perm_apply":

        if user_choice and "auto" in user_choice.lower():
            cmds = [
                "chmod 500 /etc/wazuh-dashboard/certs",
                "chmod 400 /etc/wazuh-dashboard/certs/*",
                "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs",
                "systemctl restart wazuh-dashboard",
            ]
            for cmd in cmds:
                run_command(cmd)

            dir_perms  = run_command("ls -ld /etc/wazuh-dashboard/certs") or ""
            file_perms = run_command("ls -l /etc/wazuh-dashboard/certs")  or ""

            response["display"] = (
                "Permissions fixed and wazuh-dashboard restarted.\n\n"
                f"Directory:\n{dir_perms}\n\n"
                f"Files:\n{file_perms}\n\n"
                "Shall we now check the dashboard status?"
            )
            response["ask"]  = ["Check dashboard status? (yes)"]
            context["stage"] = "dashboard_status"
            return response  # dashboard_error_flow handles dashboard_status

        else:
            response["display"] = (
                "Run these commands manually:\n\n"
                "  chmod 500 /etc/wazuh-dashboard/certs\n"
                "  chmod 400 /etc/wazuh-dashboard/certs/*\n"
                "  chown -R wazuh-dashboard:wazuh-dashboard "
                "/etc/wazuh-dashboard/certs\n"
                "  systemctl restart wazuh-dashboard\n\n"
                "Let me know when done."
            )
            response["ask"]  = ["Done? (done)"]
            context["stage"] = "dash_cert_perm_final"
            return response

    # -------------------------------------------------------------------------
    # DASH CERT PERM FINAL (manual path done confirmation)
    # -------------------------------------------------------------------------
    if context.get("stage") == "dash_cert_perm_final":

        response["display"] = (
            "Permissions updated.\n\n"
            "Shall we now check the dashboard status?"
        )
        response["ask"]  = ["Check dashboard status? (yes)"]
        context["stage"] = "dashboard_status"
        return response  # dashboard_error_flow handles dashboard_status
