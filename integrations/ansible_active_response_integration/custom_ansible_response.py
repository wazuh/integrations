#!/usr/bin/env python3
import os
import sys
import json
import datetime
import subprocess
from pathlib import PureWindowsPath, PurePosixPath

LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3
OS_SUCCESS = 0
OS_INVALID = -1

class Message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_log(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])) if "active-response" in ar_name else ar_name)
        log_file.write(f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {ar_name_posix}: {msg}\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_log(argv[0], f"Received: {input_str}")

    try:
        data = json.loads(input_str)
    except ValueError:
        write_log(argv[0], "Decoding JSON failed")
        msg = Message()
        msg.command = OS_INVALID
        return msg

    msg = Message()
    msg.alert = data.get("parameters", {}).get("alert", {})
    command = data.get("command", "")

    if command == "add":
        msg.command = ADD_COMMAND
    elif command == "delete":
        msg.command = DELETE_COMMAND
    else:
        msg.command = OS_INVALID
        write_log(argv[0], f"Invalid command: {command}")

    return msg

def main(argv):
    write_log(argv[0], "Active response started")

    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)

    alert = msg.alert
    srcip = alert.get("data", {}).get("srcip") or alert.get("srcip")

    if not srcip:
        write_log(argv[0], "No srcip found in alert")
        sys.exit(OS_INVALID)

    write_log(argv[0], f"Source IP to block: {srcip}")

    if msg.command == ADD_COMMAND:
        # Run Ansible playbook with IP as extra var
        ansible_command = [
            "ansible-playbook",
            "/etc/ansible/roles/wazuh-ansible/playbooks/block_ip.yml",
            "-e", f"ip_to_block={srcip}"
        ]

        try:
            write_log(argv[0], f"Running: {' '.join(ansible_command)}")
            result = subprocess.run(ansible_command, capture_output=True, text=True)
            write_log(argv[0], f"Return code: {result.returncode}")
            write_log(argv[0], f"stdout: {result.stdout}")
            write_log(argv[0], f"stderr: {result.stderr}")
        except Exception as e:
            write_log(argv[0], f"Error executing Ansible: {str(e)}")

    elif msg.command == DELETE_COMMAND:
        write_log(argv[0], "Delete command received — no action defined")

    write_log(argv[0], "Active response ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)