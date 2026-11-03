# kill-process.py - Wazuh custom active response for Windows (lab use)
# extra_args[0] selects the PID field: processId, parentProcessId or sourceProcessId
import sys, json, datetime, subprocess

AR_NAME = "active-response/bin/kill-process.exe"
LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
IMAGE_FIELD = {"processId": "image", "parentProcessId": "parentImage", "sourceProcessId": "sourceImage"}
PROTECTED = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
             "lsass.exe", "svchost.exe", "explorer.exe", "wmiprvse.exe", "wazuh-agent.exe", "sysmon64.exe"}

def log(text):
    with open(LOG_FILE, "a") as f:
        f.write(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " " + AR_NAME + ": " + text + "\n")

def main():
    msg = json.loads(sys.stdin.readline())
    if msg.get("command") != "add":
        return
    alert = msg["parameters"]["alert"]
    field = (msg["parameters"].get("extra_args") or ["processId"])[0]

    print(json.dumps({"version": 1, "origin": {"name": AR_NAME, "module": "active-response"},
                      "command": "check_keys", "parameters": {"keys": [alert["rule"]["id"]]}}))
    sys.stdout.flush()
    if json.loads(sys.stdin.readline()).get("command") != "continue":
        return

    ev = alert["data"]["win"]["eventdata"]
    pid = ev.get(field)
    image = ev.get(IMAGE_FIELD.get(field, "image"), "")
    name = image.replace("\\\\", "\\").split("\\")[-1].lower()
    if not pid or name in PROTECTED:
        log(json.dumps(msg) + " kill-process: skipped " + name)
        return
    r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(int(pid))], capture_output=True, text=True)
    result = "killed" if r.returncode == 0 else "failed"
    log(json.dumps(msg) + " kill-process: " + result + " " + name + " PID " + str(pid))

if __name__ == "__main__":
    main()
