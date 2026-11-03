# remove-threat.py - deletes the file VirusTotal flagged (Wazuh active response, lab use)
import sys, json, datetime, os

AR_NAME = "active-response/bin/remove-threat.exe"
LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"

def log(text):
    with open(LOG_FILE, "a") as f:
        f.write(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " " + AR_NAME + ": " + text + "\n")

def main():
    msg = json.loads(sys.stdin.readline())
    if msg.get("command") != "add":
        return
    alert = msg["parameters"]["alert"]
    print(json.dumps({"version": 1, "origin": {"name": AR_NAME, "module": "active-response"},
                      "command": "check_keys", "parameters": {"keys": [alert["rule"]["id"]]}}))
    sys.stdout.flush()
    if json.loads(sys.stdin.readline()).get("command") != "continue":
        return
    path = alert["data"]["virustotal"]["source"]["file"]
    try:
        if os.path.isfile(path) and not os.path.islink(path):
            os.remove(path)
            log(json.dumps(msg) + " Successfully removed threat")
        else:
            log(json.dumps(msg) + " Error removing threat")
    except OSError:
        log(json.dumps(msg) + " Error removing threat")

if __name__ == "__main__":
    main()
