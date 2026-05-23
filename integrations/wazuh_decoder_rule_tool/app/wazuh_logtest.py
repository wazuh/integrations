import subprocess
import os

WAZUH_HOST = "127.0.0.1"
WAZUH_PORT = "2222"
WAZUH_USER = "vagrant"

# read from environment variable
WAZUH_LOGTEST = os.getenv("WAZUH_LOGTEST_PATH", "/var/ossec/bin/wazuh-logtest")


def run_logtest(log_line):
    cmd = [
        "ssh",
        "-p", WAZUH_PORT,
        f"{WAZUH_USER}@{WAZUH_HOST}",
        f"sudo {WAZUH_LOGTEST}"
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=log_line + "\n",
            text=True,
            capture_output=True,
            timeout=20
        )
    except subprocess.TimeoutExpired:
        return {"returncode": None, "output": "wazuh-logtest is not accessible: SSH command timed out"}
    except FileNotFoundError:
        return {"returncode": None, "output": "wazuh-logtest is not accessible: ssh binary not found"}
    except Exception as e:
        return {"returncode": None, "output": f"wazuh-logtest is not accessible: {e}"}

    output = (proc.stdout or "") + (proc.stderr or "")

    return {
        "returncode": proc.returncode,
        "output": output
    }


if __name__ == "__main__":
    test_log = "Jun 15 02:04:59 combo sshd(pam_unix)[20892]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root"

    result = run_logtest(test_log)

    print("Return code:", result["returncode"])
    print("---- OUTPUT ----")
    print(result["output"])