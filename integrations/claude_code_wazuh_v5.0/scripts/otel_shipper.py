#!/usr/bin/env python3
import argparse
import json
import time


def flatten_value(value):
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return value["intValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "doubleValue" in value:
        return value["doubleValue"]
    if "arrayValue" in value:
        return value["arrayValue"]
    return None


def sanitize_key(key):
    return key.replace(".", "_")


def attrs_to_dict(attributes):
    flat = {}
    for attribute in attributes:
        flat[sanitize_key(attribute["key"])] = flatten_value(attribute.get("value", {}))
    return flat


def flatten_export(export):
    records = []
    for resource_logs in export.get("resourceLogs", []):
        resource_attrs = attrs_to_dict(resource_logs.get("resource", {}).get("attributes", []))
        for scope_logs in resource_logs.get("scopeLogs", []):
            scope_name = scope_logs.get("scope", {}).get("name", "")
            for log_record in scope_logs.get("logRecords", []):
                flat = dict(resource_attrs)
                flat["scope_name"] = scope_name
                flat["event_body"] = log_record.get("body", {}).get("stringValue", "")
                flat["timeUnixNano"] = log_record.get("timeUnixNano", "")
                flat.update(attrs_to_dict(log_record.get("attributes", [])))
                records.append(flat)
    return records


def ship_line(line, out_handle):
    line = line.strip()
    if not line:
        return
    try:
        export = json.loads(line)
    except json.JSONDecodeError:
        return
    for record in flatten_export(export):
        out_handle.write(json.dumps(record, sort_keys=True) + "\n")
    out_handle.flush()


def run_once(in_path, out_path):
    with open(in_path) as in_handle, open(out_path, "a") as out_handle:
        for line in in_handle:
            ship_line(line, out_handle)


def run_follow(in_path, out_path, poll_seconds):
    with open(out_path, "a") as out_handle:
        in_handle = open(in_path)
        in_handle.seek(0, 2)
        while True:
            line = in_handle.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            ship_line(line, out_handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path")
    parser.add_argument("out_path")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if args.follow:
        run_follow(args.in_path, args.out_path, args.poll_seconds)
    else:
        run_once(args.in_path, args.out_path)


if __name__ == "__main__":
    main()
