#!/usr/bin/env bash
# Smoke-test a ReconIP server: health, scan lifecycle, report, metrics.
# Usage: RECONIP_API_TOKEN=secret ./server-smoke.sh [base_url]
set -u
BASE="${1:-http://127.0.0.1:8080}"
AUTH=()
if [ -n "${RECONIP_API_TOKEN:-}" ]; then AUTH=(-H "Authorization: Bearer $RECONIP_API_TOKEN"); fi

echo "== health";            curl -sf "${AUTH[@]}" "$BASE/health" | head -c 200; echo
echo "== start scan";        JID=$(curl -sf "${AUTH[@]}" -X POST "$BASE/scan" \
  -H 'Content-Type: application/json' -d '{"target":"8.8.8.8"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")
echo "job: $JID"
for _ in $(seq 1 30); do
  STATE=$(curl -sf "${AUTH[@]}" "$BASE/scan/$JID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('state'))")
  echo "state: $STATE"; [ "$STATE" = COMPLETED ] || [ "$STATE" = FAILED ] && break; sleep 10
done
echo "== report keys";       curl -sf "${AUTH[@]}" "$BASE/scan/$JID/report" | python3 -c "import sys,json; print(sorted(json.load(sys.stdin).keys()))"
echo "== metrics (prom)";    curl -sf "${AUTH[@]}" -H 'Accept: text/plain' "$BASE/metrics" | head -6
