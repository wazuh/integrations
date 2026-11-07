#!/usr/bin/env bash
# Capture samples from a scratch Agentmetry recorder, then test them on a real
# Wazuh manager container. Run from the integration directory, in a throwaway
# environment such as a GitHub Codespace. Needs Docker and Python 3.
set -euo pipefail

if [ -z "${CODESPACES:-}" ] && [ "${ALLOW_OUTSIDE_CODESPACE:-}" != "1" ]; then
  echo "Refusing to run outside a Codespace: this starts a recorder and a Wazuh container." >&2
  echo "Set ALLOW_OUTSIDE_CODESPACE=1 only on a machine with no recorder of its own." >&2
  exit 1
fi

AGENTMETRY_VERSION="${AGENTMETRY_VERSION:-0.10.6}"
WAZUH_IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.9}"
CONTAINER=agentmetry-wazuh-test
PORT=8123
PKG="$(pwd)"
WORK="$(mktemp -d)"
export AGENTMETRY_DATA_DIR="$WORK/data"
export AGENTMETRY_AUTH_DISABLED=1
mkdir -p "$AGENTMETRY_DATA_DIR" "$PKG/test-results"

echo "== Installing agentmetry $AGENTMETRY_VERSION from PyPI"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "agentmetry==$AGENTMETRY_VERSION"
AM="$WORK/venv/bin/agentmetry"

cleanup() {
  (cd "$WORK" && "$AM" --port "$PORT" stop >/dev/null 2>&1) || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Starting a scratch recorder"
(cd "$WORK" && "$AM" --port "$PORT" start)
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 1
done

echo "== Replaying the attack corpus through the ingest route"
TRAIL="$AGENTMETRY_DATA_DIR/audit-forward.jsonl"
(cd "$WORK" && "$WORK/venv/bin/python" "$PKG/scripts/capture_samples.py" \
  --base-url "http://127.0.0.1:$PORT" \
  --trail "$TRAIL" \
  --rules "$PKG/ruleset/rules/agentmetry_rules.xml" \
  --out "$PKG") | tee "$PKG/test-results/capture.txt"

echo "== Verifying the chain of the trail the samples came from"
(cd "$WORK" && "$AM" verify --trail "$TRAIL") | tee "$PKG/test-results/verify.txt"

echo "== Starting $WAZUH_IMAGE"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" "$WAZUH_IMAGE" >/dev/null

wait_for_manager() {
  local status
  for _ in $(seq 1 90); do
    # wazuh-control exits non-zero while any optional daemon is off, so read its
    # output rather than its exit code.
    status="$(docker exec "$CONTAINER" /var/ossec/bin/wazuh-control status 2>/dev/null || true)"
    if grep -q "wazuh-analysisd is running" <<<"$status"; then
      sleep 5
      return 0
    fi
    sleep 5
  done
  echo "wazuh-analysisd did not start" >&2
  docker logs --tail 40 "$CONTAINER" >&2
  return 1
}
wait_for_manager
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control info -v | tee "$PKG/test-results/wazuh-version.txt"

# The vulnerability scanner downloads about 18 GB of content, which filled a 32 GB
# disk. These tests do not use it.
echo "== Turning off the vulnerability scanner for this test"
docker exec "$CONTAINER" sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/s#<enabled>yes</enabled>#<enabled>no</enabled>#' /var/ossec/etc/ossec.conf
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null
wait_for_manager
docker exec "$CONTAINER" sh -c 'rm -rf /var/ossec/tmp/* /var/ossec/queue/vd/*' || true

echo "== Installing the rules"
docker cp ruleset/rules/agentmetry_rules.xml "$CONTAINER:/var/ossec/etc/rules/agentmetry_rules.xml"
docker exec "$CONTAINER" chown wazuh:wazuh /var/ossec/etc/rules/agentmetry_rules.xml

echo "== Adding a localfile block for the live test"
LIVE_LOG=/var/ossec/logs/agentmetry-test.jsonl
docker exec "$CONTAINER" sh -c "touch $LIVE_LOG && chown wazuh:wazuh $LIVE_LOG"
docker exec "$CONTAINER" sh -c "printf '<ossec_config>\n  <localfile>\n    <log_format>json</log_format>\n    <location>$LIVE_LOG</location>\n  </localfile>\n</ossec_config>\n' >> /var/ossec/etc/ossec.conf"
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null
wait_for_manager

echo "== Running every test case through wazuh-logtest"
set +e
python3 scripts/run_logtest.py --container "$CONTAINER" --ini agentmetry.ini --report test-results/logtest.md
LOGTEST=$?
set -e

echo "== Live path: appending the samples to the watched file"
docker cp sample_logs.txt "$CONTAINER:/tmp/agentmetry-samples.txt"
docker exec "$CONTAINER" sh -c "cat /tmp/agentmetry-samples.txt >> $LIVE_LOG"
sleep 30
docker exec "$CONTAINER" sh -c 'grep "\"id\":\"9976" /var/ossec/logs/alerts/alerts.json || true' > test-results/live-alerts.json
python3 - <<'PY' | tee test-results/live-summary.txt
import collections, json
counts = collections.Counter()
with open("test-results/live-alerts.json", encoding="utf-8") as handle:
    for line in handle:
        rule = json.loads(line)["rule"]
        counts[(rule["id"], rule["level"])] += 1
for (rule_id, level), count in sorted(counts.items()):
    print(rule_id, "level", level, "alerts", count)
print("distinct rules alerted:", len(counts))
PY

docker rm -f "$CONTAINER" >/dev/null
echo "== Done. logtest exit code: $LOGTEST. Results are in test-results/."
exit "$LOGTEST"
