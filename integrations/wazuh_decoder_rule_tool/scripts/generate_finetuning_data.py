"""
Generate JSONL training data from official Wazuh decoder and rule XML files.

Downloads all decoder XMLs from https://github.com/wazuh/wazuh-ruleset/decoders/
and rule XMLs from https://github.com/wazuh/wazuh-ruleset/rules/, parses them,
generates synthetic log samples that match each decoder, and produces
JSONL training pairs in OpenAI chat format.

Usage:
    python scripts/generate_finetuning_data.py [--limit N]

Output:
    data/osregex_train_full.jsonl  (all training examples)
    data/osregex_val_full.jsonl    (10% held out for validation)
"""

import json
import os
import random
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

random.seed(42)

REPO = "wazuh/wazuh-ruleset"
BRANCH = "master"
BASE_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
API_BASE = f"https://api.github.com/repos/{REPO}/contents"

CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache_decoders"
CACHE_DIR.mkdir(exist_ok=True)

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_DIR.mkdir(exist_ok=True)

SYSTEM_PROMPT = """You are a Wazuh decoder and rule XML generator. You MUST output valid Wazuh OS_Regex syntax, NOT PCRE.

## Wazuh OS_Regex Rules (CRITICAL - these differ from PCRE)

1. In OS_Regex, '.' is ALWAYS a literal dot character. It is NOT a wildcard.
2. To match "any character", use '\\.' (backslash + dot) or '\\S+' (non-space).
3. For IP addresses, use \\d+.\\d+.\\d+.\\d+ (PLAIN dots, NOT escaped).
4. To capture a field value, wrap the pattern in parentheses: (\\S+) for a word, (\\d+) for digits.
5. Quantifiers (+, *) only work on backslash-escaped sequences, NOT on bare characters.
6. '\\d' = digit, '\\S' = non-space, '\\w' = word char, '\\s' = space.
7. Alternation uses '|' like PCRE, e.g., (value1|value2).
8. Anchors ^ and $ work the same as PCRE.

## CORRECT OS_Regex Examples
| Pattern | What it matches |
|---------|----------------|
| (\\d+\\.\\d+\\.\\d+\\.\\d+) | IP address (dots are literal) |
| (\\S+) | One non-space word |
| (\\d+) | One or more digits |
| failed|success | Either "failed" or "success" |
| from\\s+\\S+ | "from", spaces, then a word |
| ^wazuh:\\s+(\\S+) | Start "wazuh: ", capture next word |

## WRONG PCRE Patterns (NEVER use these)
| Wrong Pattern | Why It's Wrong |
|--------------|----------------|
| (\\d+\\.\\d+) | In OS_Regex, '\\.' means "any char". Use plain dot '.' for literal dot. |
| (.+) | '.' is literal dot in OS_Regex, not "any char". Use (\\S+) instead. |
| .+ | Same: '.' is literal dot. Use \\.+ or \\S+ for "any chars". |

Output response in ```xml blocks with separate sections for decoder and rule XML."""


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()


def list_files(dir_path: str) -> List[Dict]:
    url = f"{API_BASE}/{dir_path}"
    return fetch_json(url)


def download_file(path: str) -> str:
    cached = CACHE_DIR / path.replace("/", "_")
    if cached.exists():
        return cached.read_text()
    url = f"{BASE_URL}/{path}"
    content = fetch_text(url)
    cached.write_text(content)
    return content


def parse_decoder_xml(xml_content: str) -> List[Dict]:
    """Parse a decoder XML file into a list of decoder dicts."""
    # Strip XML declaration and comments
    xml_content = re.sub(r'<\?xml[^>]*\?>', '', xml_content)
    xml_content = re.sub(r'<!--.*?-->', '', xml_content, flags=re.DOTALL)

    decoders = []

    # Wazuh decoder XML is NOT valid XML (multiple roots, no wrapping)
    # We extract each <decoder>...</decoder> block individually
    decoder_blocks = re.findall(r'(<decoder\b[^>]*>.*?</decoder>)', xml_content, re.DOTALL)
    if not decoder_blocks:
        # Try regex for self-closing decoders
        decoder_blocks = re.findall(r'(<decoder\b[^>]*/>)', xml_content)

    for block in decoder_blocks:
        decoder_info = {"raw": block.strip()}
        try:
            # Parse individual decoder XML
            root = ET.fromstring(block)
            decoder_info["name"] = root.get("name", "")
            decoder_info["parent"] = root.get("parent", "")

            for child in root:
                tag = child.tag
                if tag == "prematch":
                    decoder_info["prematch"] = (child.text or "").strip()
                    decoder_info["prematch_offset"] = child.get("offset", "")
                elif tag == "regex":
                    decoder_info["regex"] = (child.text or "").strip()
                    decoder_info["regex_offset"] = child.get("offset", "")
                elif tag == "order":
                    decoder_info["order"] = [f.strip() for f in (child.text or "").split(",")]
                elif tag == "plugin_decoder":
                    decoder_info["plugin_decoder"] = (child.text or "").strip()

            decoders.append(decoder_info)
        except ET.ParseError:
            pass

    return decoders


def parse_rule_xml(xml_content: str) -> List[Dict]:
    """Parse a rule XML file and extract rules with their decoder references."""
    xml_content = re.sub(r'<\?xml[^>]*\?>', '', xml_content)
    xml_content = re.sub(r'<!--.*?-->', '', xml_content, flags=re.DOTALL)

    rules = []
    group_blocks = re.findall(r'(<group\b[^>]*>.*?</group>)', xml_content, re.DOTALL)

    for group_block in group_blocks:
        rule_blocks = re.findall(r'(<rule\b[^>]*>.*?</rule>)', group_block, re.DOTALL)
        for block in rule_blocks:
            rule_info = {"raw": block.strip()}
            try:
                root = ET.fromstring(block)
                rule_info["id"] = root.get("id", "")
                rule_info["level"] = root.get("level", "")
                rule_info["decoded_as"] = root.get("decoded_as", "")

                # Get the decoder reference from <field name="decoder"> or <decoded_as>
                for child in root:
                    tag = child.tag
                    text = (child.text or "").strip()
                    if tag == "decoded_as":
                        rule_info["decoded_as"] = text
                    elif tag == "field":
                        fname = child.get("name", "")
                        if fname == "decoder":
                            rule_info["decoder"] = text
                    elif tag == "match" or tag == "regex":
                        if "match" not in rule_info:
                            rule_info["match"] = text
                    elif tag == "description":
                        rule_info.setdefault("descriptions", []).append(text)

                # Try to infer decoder name from if_sid or other context
                if not rule_info.get("decoder") and not rule_info.get("decoded_as"):
                    # Check parent group name
                    pass

                rules.append(rule_info)
            except ET.ParseError:
                pass

    return rules


def infer_log_sample_from_regex(regex: str, order: List[str]) -> Tuple[str, Dict[str, str]]:
    """Generate a synthetic log sample from an OS_Regex pattern.
    Returns (log_line, extracted_fields)."""
    # Replace capture groups with realistic values based on field name
    fields: Dict[str, str] = {}
    
    # Build a mapping from order field names to their positions
    # Find all capture groups in the regex
    capture_patterns = _find_capture_groups(regex)
    
    sample = regex
    for i, (full_group, inner_pattern) in enumerate(capture_patterns):
        field_name = order[i] if i < len(order) else f"field_{i}"
        value = _generate_value(field_name, inner_pattern)
        fields[field_name] = value
        
        # Escape the group for regex use
        escaped_full = re.escape(full_group)
        # Use regex to replace the match
        sample = re.sub(escaped_full, value, sample, count=1)
    
    # Process remaining OS_Regex patterns to literal strings
    sample = _osregex_to_literal(sample)
    
    return sample, fields


def _find_capture_groups(pattern: str) -> List[Tuple[str, str]]:
    """Find all capture groups (patterns) in an OS_Regex pattern.
    Returns list of (full_group_match, inner_pattern) tuples."""
    groups = []
    depth = 0
    start = -1
    for i, c in enumerate(pattern):
        if c == '(' and (i == 0 or pattern[i-1] != '\\'):
            if depth == 0:
                start = i
            depth += 1
        elif c == ')' and (i == 0 or pattern[i-1] != '\\'):
            depth -= 1
            if depth == 0 and start >= 0:
                groups.append((pattern[start:i+1], pattern[start+1:i]))
                start = -1
    return groups


def _generate_value(field_name: str, inner_pattern: str) -> str:
    """Generate a realistic value for a field given the OS_Regex pattern."""
    # Known field types
    if field_name in ("srcip", "dstip", "src_ip", "dst_ip", "clientip", "dest_ip", "source_ip"):
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if field_name in ("srcport", "dstport", "src_port", "dst_port", "port"):
        return str(random.randint(1, 65535))
    if field_name in ("user", "srcuser", "dstuser", "username", "src_user", "dst_user"):
        return random.choice(["admin", "root", "jdoe", "nobody", "sshd", "www-data", "postgres", "mysql"])
    if field_name in ("protocol", "proto"):
        return random.choice(["TCP", "UDP", "ICMP", "tcp", "udp", "icmp"])
    if field_name in ("action", "status", "result"):
        return random.choice(["accept", "drop", "deny", "allow", "reject", "success", "failure", "error"])
    if field_name in ("url", "uri", "path"):
        return random.choice(["/index.php", "/login", "/admin", "/api/v1/users", "/images/logo.png"])
    if field_name in ("method", "request_method"):
        return random.choice(["GET", "POST", "PUT", "DELETE"])
    if field_name in ("status_code", "response_code"):
        return str(random.choice([200, 201, 301, 400, 401, 403, 404, 500, 502, 503]))
    if "id" in field_name.lower() or "pid" in field_name.lower() or "uid" in field_name.lower() or "gid" in field_name.lower():
        return str(random.randint(0, 65535))
    if "host" in field_name.lower() or "server" in field_name.lower():
        return random.choice(["localhost", "web01", "db01", "mail.example.com", "server1"])
    if "version" in field_name.lower():
        return f"{random.randint(1,10)}.{random.randint(0,20)}.{random.randint(0,5)}"

    # Generate from pattern type
    if inner_pattern == r'\S+':
        return random.choice(["value", "test", "data", "info", "event", "session", "request", "response"])
    if inner_pattern == r'\d+':
        return str(random.randint(0, 99999))
    if '|' in inner_pattern:
        options = [o.strip() for o in inner_pattern.split('|')]
        return random.choice(options)
    if inner_pattern == r'\w+':
        return random.choice(["alpha", "beta", "gamma", "delta"])

    return random.choice(["unknown", "default", "none", "all"])


def _osregex_to_literal(pattern: str) -> str:
    """Convert an OS_Regex pattern to a literal string by replacing
    regex constructs with matching literal text. Returns a plausible
    log line that would match this pattern."""
    
    result = pattern
    
    # Step 1: Replace \\d+\\.\\d+\\.\\d+\\.\\d+ (IP with escaped dots)
    result = re.sub(r'\\\\d\+\\\\\.\\\\d\+\\\\\.\\\\d\+\\\\\.\\\\d\+', 
                    lambda m: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", 
                    result)
    # Step 2: Replace \\d+\.\\d+\.\\d+\.\\d+ (IP with unescaped dots)
    result = re.sub(r'\\\\d\+\.\\\\d\+\.\\\\d\+\.\\\\d\+', 
                    lambda m: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", 
                    result)
    
    # Step 3: Handle escaped parens \( → "(" and \) → ")"
    result = re.sub(r'\\\\\(', '(', result)
    result = re.sub(r'\\\\\)', ')', result)
    
    # Step 4: Replace \\S+ (non-space) with a word
    result = re.sub(r'\\\\S\+', lambda m: random.choice(["value", "word", "test", "data", "12345", "info", "event", "session"]), result)
    # Replace \\d+ with digits
    result = re.sub(r'\\\\d\+', lambda m: str(random.randint(0, 99999)), result)
    # Replace \\w+ with a word
    result = re.sub(r'\\\\w\+', lambda m: random.choice(["word", "name", "test", "alpha", "beta"]), result)
    # Replace \\s+ with a single space
    result = re.sub(r'\\\\s\+', ' ', result)
    
    # Step 5: Single-char replacements (do after the + variants)
    result = re.sub(r'\\\\S', lambda m: random.choice(["x", "y", "z", "a", "b"]), result)
    result = re.sub(r'\\\\d', lambda m: str(random.randint(0, 9)), result)
    result = re.sub(r'\\\\w', lambda m: random.choice(["a", "b", "x", "y", "z"]), result)
    result = re.sub(r'\\\\s', ' ', result)
    
    # Step 6: \\.+ = escaped-dot-plus = "any characters"
    result = re.sub(r'\\\\\.\+', lambda m: random.choice(["data", "text", "info", "value"]), result)
    # \\. = escaped dot = any single char
    result = re.sub(r'\\\\\.', lambda m: random.choice(["a", "x", "1", "!"]), result)
    
    # Step 7: \\d\d\d (three-digit patterns like \d\d\d) and \d\d
    result = re.sub(r'\\\\d\\\\d\\\\d', lambda m: f"{random.randint(100,999)}", result)
    result = re.sub(r'\\\\d\\\\d', lambda m: f"{random.randint(10,99)}", result)
    
    # Step 8: Handle \: \. \\ and other escaped literals → just the char
    result = re.sub(r'\\([.:\\/;,\'\"!@#%&*+=<>?\[\]{}|~`])', r'\1', result)
    
    # Step 9: Remove remaining capture group markers (parentheses)
    result = re.sub(r'[()]', '', result)
    
    # Step 10: Replace alternation markers
    # Handle patterns like "value1|value2|value3" and "prefix |prefix2 "
    for m in re.findall(r'(?:[^\s()]+\|)+[^\s()]+', result):
        options = m.split('|')
        chosen = random.choice([o for o in options if o.strip()])
        result = result.replace(m, chosen, 1)
    
    # Step 11: Replace bare .+ or .* with a short text
    result = re.sub(r'(?<!\\)\.\+', lambda m: random.choice([" data", " text", " info"]), result)
    result = re.sub(r'(?<!\\)\.\*', lambda m: random.choice([" data", " text", " info"]), result)
    
    # Step 12: Replace anchors
    result = result.replace('^', '').replace('$', '')
    
    # Step 13: Collapse multiple spaces
    result = re.sub(r'  +', ' ', result).strip()
    
    # If still empty or just dots
    if not result or result in ('.', '..', '...'):
        result = f"log entry {random.randint(1000,9999)}"
    
    return result


def generate_split_decoder_xml(decoder: Dict) -> str:
    name = decoder.get("name", "unknown")
    parent = decoder.get("parent", name)
    regex = decoder.get("regex", "")
    order = decoder.get("order", [])
    
    parts = regex.split()
    group_parts = [p for p in parts if '(' in p and ')' in p]
    
    xmls = []
    if len(group_parts) == len(order):
        for i, field in enumerate(order):
            xmls.append(f'<decoder name="{name}">\n  <parent>{parent}</parent>\n  <regex>{group_parts[i]}</regex>\n  <order>{field}</order>\n</decoder>')
    else:
        groups = _find_capture_groups(regex)
        if len(groups) == len(order):
            for i, field in enumerate(order):
                inner = groups[i][1]
                xmls.append(f'<decoder name="{name}">\n  <parent>{parent}</parent>\n  <regex>{field}=({inner})</regex>\n  <order>{field}</order>\n</decoder>')
        else:
            return decoder.get("raw", "")
            
    return "\n\n".join(xmls)


def build_training_entry(
    log_sample: str,
    decoder_xml: str,
    rule_xml: Optional[str] = None,
    extract_fields: Optional[List[str]] = None,
    split_decoders: bool = False,
) -> Dict:
    """Build a training entry in OpenAI chat format."""
    user_content = f"Generate Wazuh decoder and rule XML for the following log sample.\nExtract these fields: {', '.join(extract_fields) if extract_fields else 'None'}"
    if split_decoders:
        user_content += "\n(Split the output into separate child decoders for each field)"
    user_content += f"\n\nLog sample:\n{log_sample}"
    
    assistant_content = f"```xml\n{decoder_xml}\n```"
    if rule_xml and rule_xml.strip():
        assistant_content += f"\n\n```xml\n{rule_xml}\n```"
    
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        limit = int(sys.argv[idx + 1])

    print("Fetching decoder file list...")
    decoder_files = list_files("decoders")
    print(f"  Found {len(decoder_files)} decoder files")

    print("Fetching rule file list...")
    rule_files = list_files("rules")
    # Filter to only XML files, skip directories
    rule_files = [f for f in rule_files if f["name"].endswith(".xml")]
    print(f"  Found {len(rule_files)} rule files")

    # Parse decoders
    print("\nParsing decoders...")
    all_decoders: List[Dict] = []
    decoder_files_to_parse = decoder_files[:limit] if limit else decoder_files
    for df in decoder_files_to_parse:
        print(f"  Downloading {df['name']}...", end=" ", flush=True)
        content = download_file(df["path"])
        decoders = parse_decoder_xml(content)
        all_decoders.extend(decoders)
        print(f"{len(decoders)} decoders")

    # Filter to decoders with regex patterns
    decoders_with_regex = [d for d in all_decoders if d.get("regex")]
    print(f"  Total decoders: {len(all_decoders)}")
    print(f"  Decoders with regex: {len(decoders_with_regex)}")

    # Parse all rules
    print("\nParsing rules...")
    all_rules: List[Dict] = []
    rule_files_to_parse = rule_files[:limit] if limit else rule_files
    for rf in rule_files_to_parse:
        print(f"  Downloading {rf['name']}...", end=" ", flush=True)
        content = download_file(rf["path"])
        rules = parse_rule_xml(content)
        all_rules.extend(rules)
        print(f"{len(rules)} rules")

    print(f"  Total rules: {len(all_rules)}")

    # Group rules by decoder name
    rules_by_decoder: Dict[str, List[Dict]] = defaultdict(list)
    for rule in all_rules:
        decoder_name = rule.get("decoder") or rule.get("decoded_as") or ""
        if decoder_name:
            rules_by_decoder[decoder_name].append(rule)

    # Generate training examples
    print("\nGenerating training examples...")
    training_entries: List[Dict] = []
    failed_decoders = 0

    for i, decoder in enumerate(decoders_with_regex):
        if limit and i >= limit:
            break

        name = decoder.get("name", "unknown")
        regex = decoder.get("regex", "")
        order = decoder.get("order", [])
        prematch = decoder.get("prematch", "")
        parent = decoder.get("parent", "")

        # Skip decoders with very complex multi-group patterns that are hard to generate
        # (we still include them, the generation will just be approximate)
        
        # Generate synthetic log sample
        try:
            log_sample, fields = infer_log_sample_from_regex(regex, order)
        except Exception as e:
            failed_decoders += 1
            continue

        # Prepend prematch content if available
        if prematch:
            prematch_literal = _osregex_to_literal(prematch)
            log_sample = prematch_literal + " " + log_sample if log_sample else prematch_literal

        # Build decoder XML for the training entry (the whole decoder block)
        decoder_raw = decoder.get("raw", "")
        
        # Find matching rules
        matched_rules = rules_by_decoder.get(name, [])
        rule_raw = ""
        if matched_rules:
            rule_raw = matched_rules[0].get("raw", "")

        extract_fields = order if order else list(fields.keys())
        
        entry = build_training_entry(
            log_sample=log_sample,
            decoder_xml=decoder_raw,
            rule_xml=rule_raw if rule_raw else None,
            extract_fields=extract_fields,
            split_decoders=False,
        )
        training_entries.append(entry)
        
        # 50% chance to also generate a split decoders example for training
        if len(extract_fields) > 1 and random.random() < 0.5:
            split_xml = generate_split_decoder_xml(decoder)
            if split_xml and split_xml != decoder_raw:
                split_entry = build_training_entry(
                    log_sample=log_sample,
                    decoder_xml=split_xml,
                    rule_xml=rule_raw if rule_raw else None,
                    extract_fields=extract_fields,
                    split_decoders=True,
                )
                training_entries.append(split_entry)

    print(f"  Generated: {len(training_entries)} examples")
    if failed_decoders:
        print(f"  Failed: {failed_decoders} decoders")

    # Shuffle and split
    random.shuffle(training_entries)
    split_idx = max(1, int(len(training_entries) * 0.9))
    train = training_entries[:split_idx]
    val = training_entries[split_idx:]

    # Write output
    train_path = OUTPUT_DIR / "osregex_train_full.jsonl"
    val_path = OUTPUT_DIR / "osregex_val_full.jsonl"

    with open(train_path, "w") as f:
        for entry in train:
            f.write(json.dumps(entry) + "\n")

    with open(val_path, "w") as f:
        for entry in val:
            f.write(json.dumps(entry) + "\n")

    print(f"\nOutput:")
    print(f"  Train: {train_path} ({len(train)} examples)")
    print(f"  Val:   {val_path} ({len(val)} examples)")

    # Stats
    print(f"\nStats:")
    total_regex_decoders = len(decoders_with_regex)
    print(f"  Decoder files parsed: {len(decoder_files)}")
    print(f"  All decoders: {len(all_decoders)}")
    print(f"  Decoders with regex: {total_regex_decoders}")
    print(f"  Rules parsed: {len(all_rules)}")
    success_rate = len(training_entries) / total_regex_decoders * 100 if total_regex_decoders else 0
    print(f"  Training examples generated: {len(training_entries)} ({success_rate:.0f}% of decoders with regex)")


if __name__ == "__main__":
    main()
