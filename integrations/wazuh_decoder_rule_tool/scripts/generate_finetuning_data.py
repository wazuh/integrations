"""
Generate Ollama-compatible fine-tuning conversation pairs.

Reads:
  - data/datasets/train.jsonl  (rules-testing + feedback pairs)
  - data/datasets/feedback.jsonl  (approved user corrections)
  - data/datasets/feedback_rejections.jsonl  (rejections with corrections in notes)

Outputs:
  - data/datasets/ollama_finetune.jsonl
    Each line: {"prompt": "<user prompt>", "response": "<assistant XML>"}

Usage:
  python scripts/generate_finetuning_data.py

The output is used in two ways:
  1. Embedded as MESSAGE directives in Modelfile.finetune for in-context training
  2. For reference when manually curating additional examples
"""

from __future__ import annotations

import json
import random
import textwrap
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "datasets"

TRAIN_PATH = DATA_DIR / "train.jsonl"
FEEDBACK_PATH = DATA_DIR / "feedback.jsonl"
REJECTIONS_PATH = DATA_DIR / "feedback_rejections.jsonl"
OUTPUT_PATH = DATA_DIR / "ollama_finetune.jsonl"

# ── Prompt templates ──────────────────────────────────────────────────────────

USER_TMPL = """\
Generate Wazuh decoder and rule XML for the following log sample.
Extract these fields: {fields}

Log:
{log}"""

USER_TMPL_NO_FIELDS = """\
Generate Wazuh decoder and rule XML for the following log sample.

Log:
{log}"""

# ── XML generation from decoder dict ─────────────────────────────────────────

def _build_decoder_xml(decoder: Dict) -> str:
    """Build minimal valid decoder XML from a decoder dict."""
    name = decoder.get("name") or "myapp-event"
    parent = decoder.get("parent")
    program_name = decoder.get("program_name")
    prematch = decoder.get("prematch")
    regex = decoder.get("regex")
    order = decoder.get("order") or []

    lines: List[str] = []

    # If there's a parent specified and no parent decoder in the dict, emit parent first
    if parent and parent != name:
        lines.append(f'<decoder name="{parent}">')
        if program_name:
            lines.append(f"  <program_name>{program_name}</program_name>")
        elif prematch:
            lines.append(f"  <prematch>^{prematch}</prematch>")
        lines.append("</decoder>")

    # Child (or standalone) decoder
    lines.append(f'<decoder name="{name}">')
    if parent and parent != name:
        lines.append(f"  <parent>{parent}</parent>")
    if prematch:
        if parent:
            lines.append(f'  <prematch offset="after_parent">^{prematch}</prematch>')
        else:
            lines.append(f"  <prematch>^{prematch}</prematch>")
    if regex:
        offset = 'offset="after_prematch"' if prematch else ""
        lines.append(f"  <regex {offset}>{regex}</regex>".replace("<regex >", "<regex>"))
    if order:
        lines.append(f"  <order>{', '.join(order)}</order>")
    lines.append("</decoder>")

    return "\n".join(lines)


def _build_rule_xml(decoder: Dict, rule_id: int = 100100) -> str:
    """Build a minimal rule XML for the decoder."""
    name = decoder.get("name") or "myapp-event"
    parent = decoder.get("parent") or name
    return textwrap.dedent(f"""\
        <rule id="{rule_id}" level="5">
          <decoded_as>{parent}</decoded_as>
          <description>{name}: event detected.</description>
          <group>custom,</group>
        </rule>""")


def _make_xml_block(decoder: Dict, rule_id: int = 100100) -> str:
    decoder_xml = _build_decoder_xml(decoder)
    rule_xml = _build_rule_xml(decoder, rule_id)
    return f"```xml\n{decoder_xml}\n{rule_xml}\n```"


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_train_records() -> List[Dict]:
    if not TRAIN_PATH.exists():
        return []
    records = []
    with TRAIN_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def load_feedback_records() -> List[Dict]:
    if not FEEDBACK_PATH.exists():
        return []
    records = []
    with FEEDBACK_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if rec.get("decoder") and rec.get("log"):
                    records.append(rec)
            except json.JSONDecodeError:
                continue
    return records


def load_rejection_corrections() -> List[Dict]:
    """Load rejections that have a corrected regex in notes."""
    if not REJECTIONS_PATH.exists():
        return []
    records = []
    with REJECTIONS_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            notes = (rec.get("notes") or "").strip()
            log = (rec.get("log") or "").strip()
            app_name = (rec.get("app_name") or "myapp").strip()
            fields = rec.get("extract_fields") or []
            if notes and len(notes) >= 10 and log:
                records.append({
                    "log": log,
                    "extract_fields": fields,
                    "decoder": {
                        "name": f"{app_name}-event",
                        "parent": app_name,
                        "prematch": app_name,
                        "regex": notes,
                        "order": fields,
                    },
                })
    return records


# ── Hand-curated high-quality examples ───────────────────────────────────────
# These are carefully crafted to cover log types missing from the auto-generated data.

HAND_CURATED: List[Dict] = [
    # ── JSON structured log ───────────────────────────────────────────────────
    {
        "log": '{"ts":1573804908.676,"uid":"C4XJwR1","id.orig_h":"10.0.0.1","id.orig_p":56980,"id.resp_h":"10.0.0.5","id.resp_p":443,"proto":"tcp","bro_engine":"SSL"}',
        "extract_fields": [],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="json">
              <prematch>^{\\s*\"</prematch>
            </decoder>
            <rule id="100200" level="3">
              <decoded_as>json</decoded_as>
              <description>JSON log event.</description>
              <group>custom,</group>
            </rule>
            ```"""),
    },
    # ── DHCP log with MAC address ─────────────────────────────────────────────
    {
        "log": "May 11 14:26:59 pmc-ib-a dhcpd[2660669]: DHCPACK on 192.168.7.89 to 00:1A:2B:3C:4D:5E (S24-Ultra) via eth2",
        "extract_fields": ["srcip", "mac_address", "hostname"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="dhcpd">
              <program_name>^dhcpd</program_name>
            </decoder>
            <decoder name="dhcpd-ack">
              <parent>dhcpd</parent>
              <prematch>^DHCPACK on </prematch>
              <regex offset="after_prematch">^(\\S+) to (\\S+) \\((\\S+)\\)</regex>
              <order>srcip, mac_address, hostname</order>
            </decoder>
            <rule id="100201" level="3">
              <decoded_as>dhcpd</decoded_as>
              <match>DHCPACK</match>
              <description>DHCP ACK: IP assigned to host.</description>
              <group>custom,network,</group>
            </rule>
            ```"""),
    },
    # ── ZooKeeper / Java app log ──────────────────────────────────────────────
    {
        "log": "2015-07-29 19:04:29,071 - WARN  [SendWorker:188978561024:QuorumCnxManager$SendWorker@688] - Send worker leaving thread",
        "extract_fields": ["logtime", "loglevel", "message"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="zookeeper">
              <prematch>^\\d\\d\\d\\d-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d</prematch>
            </decoder>
            <decoder name="zookeeper-log">
              <parent>zookeeper</parent>
              <prematch offset="after_parent">^\\d\\d\\d\\d-\\d\\d-\\d\\d </prematch>
              <regex offset="after_parent">^(\\d\\d\\d\\d-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d,\\d+) - (\\S+)\\s+\\[.+\\] - (\\.+)</regex>
              <order>logtime, loglevel, message</order>
            </decoder>
            <rule id="100202" level="3">
              <decoded_as>zookeeper</decoded_as>
              <description>ZooKeeper application log event.</description>
              <group>custom,application,</group>
            </rule>
            ```"""),
    },
    # ── OpenSearch / structured key=value log ─────────────────────────────────
    {
        "log": "[2026-04-29T04:29:06,056][INFO ][o.o.s.c.Task] [node-1] Starting housekeeping task for auto refresh streaming jobs.",
        "extract_fields": ["logtime", "loglevel", "message"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="opensearch">
              <prematch>^\\[\\d\\d\\d\\d-\\d\\d-\\d\\dT</prematch>
            </decoder>
            <decoder name="opensearch-log">
              <parent>opensearch</parent>
              <regex offset="after_parent">^\\[(\\d\\d\\d\\d-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d,\\d+)\\]\\[(\\S+)\\s*\\]\\[\\S+\\] \\[\\S+\\] (\\.+)</regex>
              <order>logtime, loglevel, message</order>
            </decoder>
            <rule id="100203" level="3">
              <decoded_as>opensearch</decoded_as>
              <description>OpenSearch node log event.</description>
              <group>custom,application,</group>
            </rule>
            ```"""),
    },
    # ── Payments service structured key=value ─────────────────────────────────
    {
        "log": "level=ERROR service=payments-service event=suspicious_transaction transaction_id=TX-993882 user=sakib amount=999999 currency=EUR srcip=203.0.113.77 risk_score=92 action=blocked",
        "extract_fields": ["level", "service", "event", "user", "srcip", "action"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="kv-log">
              <prematch>^level=</prematch>
            </decoder>
            <decoder name="kv-log-fields">
              <parent>kv-log</parent>
              <regex offset="after_parent">^level=(\\S+) service=(\\S+) event=(\\S+) .+ user=(\\S+) .+ srcip=(\\S+) .+ action=(\\S+)</regex>
              <order>status, program_name, id, user, srcip, action</order>
            </decoder>
            <rule id="100204" level="10">
              <decoded_as>kv-log</decoded_as>
              <field name="event">suspicious_transaction</field>
              <description>Suspicious transaction blocked by payments service.</description>
              <group>custom,financial,fraud,</group>
            </rule>
            ```"""),
    },
    # ── Windows Sysmon EventID 1 ──────────────────────────────────────────────
    {
        "log": "2014 Dec 20 09:29:47 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(1): Microsoft-Windows-Sysmon: SYSTEM: NT AUTHORITY: WIN-HOST: Process Create:  Image: C:\\Windows\\system32\\svchost.exe  CommandLine: \"svchost.exe -k defragsvc\"  User: NT AUTHORITY\\SYSTEM",
        "extract_fields": ["user"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="windows">
              <program_name>^WinEvtLog</program_name>
            </decoder>
            <rule id="100205" level="3">
              <decoded_as>windows</decoded_as>
              <match>Microsoft-Windows-Sysmon</match>
              <description>Sysmon: Process Create event.</description>
              <group>custom,sysmon,process_creation,</group>
            </rule>
            ```"""),
    },
    # ── SCADA / ICS log ───────────────────────────────────────────────────────
    {
        "log": "May 16 14:22:31 plc-gateway01 scada-engine[2241]: ALERT Modbus unauthorized write request detected from 10.10.50.24 function_code=0x10 register=40123",
        "extract_fields": ["srcip", "function_code"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="scada-engine">
              <program_name>^scada-engine</program_name>
            </decoder>
            <decoder name="scada-modbus-alert">
              <parent>scada-engine</parent>
              <prematch offset="after_parent">^ALERT Modbus</prematch>
              <regex offset="after_prematch">^ unauthorized write request detected from (\\S+) function_code=(\\S+)</regex>
              <order>srcip, id</order>
            </decoder>
            <rule id="100206" level="12">
              <decoded_as>scada-engine</decoded_as>
              <match>ALERT Modbus unauthorized write</match>
              <description>SCADA: Unauthorized Modbus write request detected.</description>
              <group>custom,ics,scada,</group>
            </rule>
            ```"""),
    },
    # ── Nginx access log ──────────────────────────────────────────────────────
    {
        "log": '203.0.113.10 - alice [01/Jun/2026:09:12:34 +0000] "GET /api/v1/users HTTP/1.1" 200 512 "-" "curl/7.81.0"',
        "extract_fields": ["srcip", "user", "url", "status"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="nginx-access">
              <prematch>^\\S+ \\S+ \\S+ \\[</prematch>
            </decoder>
            <decoder name="nginx-access-fields">
              <parent>nginx-access</parent>
              <regex offset="after_parent">^(\\S+) \\S+ (\\S+) \\[\\S+ \\S+\\] \"\\S+ (\\S+) HTTP\\S+\" (\\d+)</regex>
              <order>srcip, user, url, status</order>
            </decoder>
            <rule id="100207" level="3">
              <decoded_as>nginx-access</decoded_as>
              <description>Nginx: Access log event.</description>
              <group>custom,web,access_log,</group>
            </rule>
            ```"""),
    },
    # ── Firewall drop/accept ──────────────────────────────────────────────────
    {
        "log": "Jun  2 08:44:15 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22",
        "extract_fields": ["srcip", "dstip", "protocol", "srcport", "dstport"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="ufw">
              <prematch>kernel: \\[UFW </prematch>
            </decoder>
            <decoder name="ufw-block">
              <parent>ufw</parent>
              <prematch offset="after_parent">\\[UFW BLOCK\\]</prematch>
              <regex offset="after_prematch">^ IN=\\S+ OUT=\\S* .+ SRC=(\\S+) DST=(\\S+) PROTO=(\\S+) SPT=(\\d+) DPT=(\\d+)</regex>
              <order>srcip, dstip, protocol, srcport, dstport</order>
            </decoder>
            <rule id="100208" level="7">
              <decoded_as>ufw</decoded_as>
              <match>UFW BLOCK</match>
              <description>UFW: Packet blocked by firewall.</description>
              <group>custom,firewall,</group>
            </rule>
            ```"""),
    },
    # ── Sudo command execution ────────────────────────────────────────────────
    {
        "log": "Jun  2 09:00:01 server01 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/passwd",
        "extract_fields": ["srcuser", "dstuser", "command"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="sudo">
              <program_name>^sudo</program_name>
            </decoder>
            <decoder name="sudo-fields">
              <parent>sudo</parent>
              <prematch>\\s</prematch>
              <regex>^\\s*(\\S+)\\s*:</regex>
              <order>srcuser</order>
              <fts>name,srcuser,location</fts>
            </decoder>
            <decoder name="sudo-fields">
              <parent>sudo</parent>
              <regex offset="after_regex">USER=(\\S+)</regex>
              <order>dstuser</order>
            </decoder>
            <decoder name="sudo-fields">
              <parent>sudo</parent>
              <regex offset="after_regex">COMMAND=(\\.+)</regex>
              <order>command</order>
            </decoder>
            <rule id="100209" level="5">
              <decoded_as>sudo</decoded_as>
              <description>Sudo: Command executed as another user.</description>
              <group>custom,sudo,privilege_escalation,</group>
            </rule>
            ```"""),
    },
    # ── CEF format ────────────────────────────────────────────────────────────
    {
        "log": "CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|Threat Detection|8|src=203.0.113.50 dst=10.0.0.5 spt=4444 dpt=443 proto=TCP act=block",
        "extract_fields": ["srcip", "dstip", "srcport", "dstport", "protocol", "action"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="cef">
              <prematch>^CEF:</prematch>
            </decoder>
            <decoder name="cef-fields">
              <parent>cef</parent>
              <regex offset="after_parent">^\\d\\|.+\\|.+\\|.+\\|.+\\|.+\\|.+\\|.+ src=(\\S+) dst=(\\S+) spt=(\\d+) dpt=(\\d+) proto=(\\S+) act=(\\S+)</regex>
              <order>srcip, dstip, srcport, dstport, protocol, action</order>
            </decoder>
            <rule id="100210" level="8">
              <decoded_as>cef</decoded_as>
              <match>act=block</match>
              <description>CEF: Palo Alto threat blocked.</description>
              <group>custom,firewall,threat,</group>
            </rule>
            ```"""),
    },
    # ── Android/mobile app log (pipe-delimited) ────────────────────────────────
    {
        "log": "20171223-22:15:33:144|Step_SPUtils|30002312| getTodayTotalDetailSteps = 1514038440000##7013##548365",
        "extract_fields": ["logtime", "data"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="mobile-app">
              <prematch>^\\d\\d\\d\\d\\d\\d\\d\\d-\\d\\d:\\d\\d:\\d\\d</prematch>
            </decoder>
            <decoder name="mobile-app-step">
              <parent>mobile-app</parent>
              <prematch offset="after_parent">|Step_SPUtils|</prematch>
              <regex offset="after_parent">^(\\.+)\\|Step_SPUtils\\|\\d+\\| getTodayTotalDetailSteps = (\\.+)</regex>
              <order>logtime, data</order>
            </decoder>
            <rule id="100211" level="3">
              <decoded_as>mobile-app</decoded_as>
              <description>Mobile app: Step data reported.</description>
              <group>custom,mobile,</group>
            </rule>
            ```"""),
    },
    # ── Failed SSH login ──────────────────────────────────────────────────────
    {
        "log": "Jun  2 10:01:15 server01 sshd[12345]: Failed password for invalid user admin from 203.0.113.77 port 54321 ssh2",
        "extract_fields": ["user", "srcip", "srcport"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="sshd">
              <program_name>^sshd</program_name>
            </decoder>
            <decoder name="ssh-failed">
              <parent>sshd</parent>
              <prematch>^Failed \\S+ </prematch>
              <regex offset="after_prematch">^for (?:invalid user )?(\\S+) from (\\S+) port (\\d+)</regex>
              <order>user, srcip, srcport</order>
            </decoder>
            <rule id="100212" level="5">
              <decoded_as>sshd</decoded_as>
              <match>Failed password|Failed none</match>
              <description>SSHD: Authentication failed.</description>
              <group>custom,authentication_failed,pci_dss_10.2.4,</group>
            </rule>
            ```"""),
    },
    # ── Custom app failed login ───────────────────────────────────────────────
    {
        "log": "Dec 25 20:45:02 MyHost myapp[12345]: User 'admin' failed login from '192.168.1.100'",
        "extract_fields": ["user", "srcip"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="myapp">
              <program_name>^myapp</program_name>
            </decoder>
            <decoder name="myapp-login-failed">
              <parent>myapp</parent>
              <prematch offset="after_parent">^User '\\S+' failed login</prematch>
              <regex offset="after_prematch">^User '(\\S+)' failed login from '(\\S+)'</regex>
              <order>user, srcip</order>
            </decoder>
            <rule id="100213" level="6">
              <decoded_as>myapp</decoded_as>
              <match>failed login</match>
              <description>Custom app: User authentication failed.</description>
              <group>custom,authentication_failed,</group>
            </rule>
            ```"""),
    },
    # ── TrafficLog with IP extraction using unescaped dots ─────────────────────
    # CRITICAL: OS_Regex uses '.' as literal dot. NEVER escape with \.
    {
        "log": "Dec 25 20:45:02 myhost TrafficLog[1234]: Action=LOGIN SrcIP=192.168.10.1 SrcPort=55432 DstIP=10.0.0.1 DstPort=443 Protocol=HTTPS",
        "extract_fields": ["action", "srcip", "srcport", "dstip", "dstport", "protocol"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="trafficlog">
              <program_name>^TrafficLog</program_name>
            </decoder>
            <decoder name="trafficlog-event">
              <parent>trafficlog</parent>
              <regex>Action=(\\w+) SrcIP=(\\d+.\\d+.\\d+.\\d+)</regex>
              <order>action, srcip</order>
            </decoder>
            <decoder name="trafficlog-event">
              <parent>trafficlog</parent>
              <regex>DstIP=(\\d+.\\d+.\\d+.\\d+)</regex>
              <order>dstip</order>
            </decoder>
            <decoder name="trafficlog-event">
              <parent>trafficlog</parent>
              <regex>SrcPort=(\\d+)</regex>
              <order>srcport</order>
            </decoder>
            <decoder name="trafficlog-event">
              <parent>trafficlog</parent>
              <regex>DstPort=(\\d+)</regex>
              <order>dstport</order>
            </decoder>
            <decoder name="trafficlog-event">
              <parent>trafficlog</parent>
              <regex>Protocol=(\\S+)</regex>
              <order>protocol</order>
            </decoder>
            <rule id="100215" level="5">
              <decoded_as>trafficlog</decoded_as>
              <description>TrafficLog: Network event captured.</description>
              <group>custom,network,</group>
            </rule>
            ```"""),
    },
    # ── Tomcat/Java web server ────────────────────────────────────────────────
    {
        "log": "29-Jun-2026 10:23:45.678 SEVERE [http-nio-8080-exec-1] org.apache.catalina.core.StandardWrapperValve.invoke Servlet.service() for servlet threw exception java.lang.NullPointerException",
        "extract_fields": ["logtime", "loglevel", "message"],
        "response": textwrap.dedent("""\
            ```xml
            <decoder name="tomcat">
              <prematch>^\\d\\d-\\w\\w\\w-\\d\\d\\d\\d \\d\\d:\\d\\d:\\d\\d</prematch>
            </decoder>
            <decoder name="tomcat-log">
              <parent>tomcat</parent>
              <regex offset="after_parent">^(\\d\\d-\\w\\w\\w-\\d\\d\\d\\d \\d\\d:\\d\\d:\\d\\d\\.\\d+) (\\S+) \\[\\S+\\] \\S+ (\\.+)</regex>
              <order>logtime, loglevel, message</order>
            </decoder>
            <rule id="100214" level="7">
              <decoded_as>tomcat</decoded_as>
              <field name="loglevel">SEVERE</field>
              <description>Tomcat: Severe error in servlet.</description>
              <group>custom,application,</group>
            </rule>
            ```"""),
    },
]


# ── Builder ───────────────────────────────────────────────────────────────────

def build_prompt(log: str, fields: Optional[List[str]]) -> str:
    if fields:
        return USER_TMPL.format(fields=", ".join(fields), log=log)
    return USER_TMPL_NO_FIELDS.format(log=log)


def records_to_pairs(records: List[Dict]) -> List[Dict]:
    """Convert training records that have a decoder dict into prompt/response pairs."""
    pairs = []
    for rec in records:
        log = (rec.get("log") or "").strip()
        decoder = rec.get("decoder")
        if not log or not isinstance(decoder, dict) or not decoder.get("name"):
            continue
        fields = rec.get("extract_fields") or decoder.get("order") or []
        # Skip test harness records (they don't have real decoder XML we can synthesize meaningfully)
        if decoder.get("source", "").endswith(".ini") or (rec.get("source") == "augmented_dropout"):
            continue
        prompt = build_prompt(log, fields)
        response = _make_xml_block(decoder, rule_id=random.randint(100100, 100999))
        pairs.append({"prompt": prompt, "response": response})
    return pairs


def hand_curated_pairs() -> List[Dict]:
    """Return the hand-curated high-quality examples as prompt/response pairs."""
    pairs = []
    for item in HAND_CURATED:
        log = item["log"]
        fields = item.get("extract_fields") or []
        prompt = build_prompt(log, fields)
        response = item.get("response") or _make_xml_block(item.get("decoder", {}))
        pairs.append({"prompt": prompt, "response": response})
    return pairs


def main() -> None:
    all_pairs: List[Dict] = []

    # 1. Hand-curated examples always come first — highest quality
    curated = hand_curated_pairs()
    all_pairs.extend(curated)
    print(f"  Hand-curated examples: {len(curated)}")

    # 2. Approved feedback records
    feedback_records = []
    if FEEDBACK_PATH.exists():
        with FEEDBACK_PATH.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("decoder") and rec.get("log"):
                        feedback_records.append(rec)
                except json.JSONDecodeError:
                    continue
    fb_pairs = records_to_pairs(feedback_records)
    all_pairs.extend(fb_pairs)
    print(f"  Feedback-derived examples: {len(fb_pairs)}")

    # 3. Rejection corrections
    correction_records = []
    if REJECTIONS_PATH.exists():
        with REJECTIONS_PATH.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    notes = (rec.get("notes") or "").strip()
                    log = (rec.get("log") or "").strip()
                    if notes and len(notes) >= 10 and log:
                        correction_records.append({
                            "log": log,
                            "extract_fields": rec.get("extract_fields") or [],
                            "decoder": {
                                "name": f"{rec.get('app_name', 'myapp')}-event",
                                "parent": rec.get("app_name", "myapp"),
                                "prematch": rec.get("app_name", "myapp"),
                                "regex": notes,
                                "order": rec.get("extract_fields") or [],
                            },
                        })
                except json.JSONDecodeError:
                    continue
    corr_pairs = records_to_pairs(correction_records)
    all_pairs.extend(corr_pairs)
    print(f"  Correction-derived examples: {len(corr_pairs)}")

    # Deduplicate by prompt
    seen: set = set()
    unique: List[Dict] = []
    for p in all_pairs:
        key = p["prompt"][:120]
        if key not in seen:
            seen.add(key)
            unique.append(p)

    print(f"  Total unique fine-tuning pairs: {len(unique)}")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as out:
        for pair in unique:
            out.write(json.dumps(pair, ensure_ascii=False) + "\n")
    print(f"Wrote {len(unique)} pairs to {OUTPUT_PATH}")

    # Print summary for embedding into Modelfile
    print("\n── First 3 pairs (preview) ─────────────────────────────────")
    for i, pair in enumerate(unique[:3]):
        print(f"\n--- Pair {i+1} ---")
        print("PROMPT:", pair["prompt"][:200])
        print("RESPONSE:", pair["response"][:200])


if __name__ == "__main__":
    main()
