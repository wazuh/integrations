#!/usr/bin/env bash
# Exercise the actual manager with synthetic CSP reports in an isolated Docker lab.
set -euo pipefail
cd "$(dirname "$0")/.."

image="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.10}"
manager="optimizely-csp-test-$$"
tmp="$(mktemp -d)"
trap 'docker rm -fv "$manager" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

docker create --name "$manager" "$image" >/dev/null
docker cp "$manager:/var/ossec/etc/ossec.conf" "$tmp/ossec.conf"
python3 - "$tmp/ossec.conf" <<'PY'
import sys
from pathlib import Path

config = Path(sys.argv[1])
text = config.read_text()
collector = """
  <localfile>
    <location>/var/log/optimizely-csp.jsonl</location>
    <log_format>json</log_format>
  </localfile>
"""
config.write_text(text.replace("</ossec_config>", collector + "</ossec_config>", 1))
PY
touch "$tmp/optimizely-csp.jsonl"
mkdir -p "$tmp/config/etc/rules"
cp "$tmp/ossec.conf" "$tmp/config/etc/ossec.conf"
cp ruleset/rules/optimizely_csp_rules.xml "$tmp/config/etc/rules/"
docker cp "$tmp/config" "$manager:/wazuh-config-mount"
docker cp "$tmp/optimizely-csp.jsonl" "$manager:/var/log/optimizely-csp.jsonl"
docker start "$manager" >/dev/null
for attempt in $(seq 1 90); do
  if docker exec "$manager" test -S /var/ossec/queue/sockets/logtest &&
     docker exec "$manager" sh -c 'grep -Fq "Analyzing file: '\''/var/log/optimizely-csp.jsonl'\''" /var/ossec/logs/ossec.log'; then
    break
  fi
  if [ "$attempt" = 90 ]; then
    docker logs --tail 50 "$manager" >&2
    exit 1
  fi
  sleep 2
done

docker exec "$manager" /var/ossec/bin/wazuh-control info
docker exec "$manager" /var/ossec/bin/wazuh-analysisd -t
cat > "$tmp/logtest" <<WRAPPER
#!/usr/bin/env bash
exec docker exec -i "$manager" /var/ossec/bin/wazuh-logtest
WRAPPER
chmod +x "$tmp/logtest"
python3 tests/check.py --logtest "$tmp/logtest"

# Retain the actual manager output for two positive cases and a negative control.
for fixture in 1 2 3; do
  printf '\nLogtest fixture %s\n' "$fixture"
  sed -n "${fixture}p" tests/csp.jsonl | sed 's/\[\.\]/./g' |
    jq -c -f normalize-csp.jq | "$tmp/logtest" 2>&1
done

# Send the full fixture export through logcollector, outside the logtest path.
sed 's/\[\.\]/./g' tests/csp.jsonl | jq -c -f normalize-csp.jq |
  docker exec -i "$manager" sh -c 'cat >> /var/log/optimizely-csp.jsonl'

# Wait for the live alerts and allow logcollector one additional scan interval.
for attempt in $(seq 1 30); do
  docker exec "$manager" cat /var/ossec/logs/alerts/alerts.json > "$tmp/alerts.jsonl" 2>/dev/null || true
  count="$(jq -s 'map(select(.rule.id == "100980")) | length' "$tmp/alerts.jsonl")"
  if [ "$count" -ge 2 ]; then break; fi
  sleep 2
done
sleep 3
docker exec "$manager" cat /var/ossec/logs/alerts/alerts.json > "$tmp/alerts.jsonl"
jq -es '
  map(select(.rule.id == "100980")) as $alerts
  | ($alerts | length == 2)
    and all($alerts[]; .rule.level == 10 and .decoder.name == "json"
            and .location == "/var/log/optimizely-csp.jsonl")
    and ([$alerts[].data.csp | [.disposition, .destination]] | sort
         == [["enforce", "1688360.cc"], ["report", "asset.5vobauua3ojpklx.icu"]])
' "$tmp/alerts.jsonl" >/dev/null

printf '\nLive manager alerts from /var/ossec/logs/alerts/alerts.json\n'
jq -c 'select(.rule.id == "100980") |
  {rule: .rule.id, level: .rule.level, decoder: .decoder.name,
   disposition: .data.csp.disposition, directive: .data.csp.directive,
   destination: .data.csp.destination, location}' "$tmp/alerts.jsonl"
