#!/usr/bin/env bash
# W3-06 -- final false-positive measurement on the FULL consolidated stack.
#
# Runs one realistic-traffic session (scripts/traffic.js --duration, no
# failed logins, no suspicious payloads) against SupportDesk, then counts
# every Sentinel X custom alert (project range 100100-100199, CONTRACT.md
# section 8) indexed by Wazuh inside the exact measure window. Any custom
# alert on pure normal traffic is a false positive; each one is reported with
# its sample document so it can be justified in the alert-qualification
# report. Native Wazuh alerts of the same window (host SCA, training.log,
# daemons...) are out of the custom-chain scope: they are listed per rule and
# per `location` so the report can show none comes from app.jsonl.
#
# Usage (on the consolidated-stack host, e.g. inside the project LXC):
#   cd /opt/sentinelx && DURATION=600 detection/tests/fp-measure.sh
# Variables:
#   BASE         app URL         (default http://localhost:3000)
#   DURATION     traffic seconds (default 600 -- CONTRACT.md section 12)
#   INDEXER_URL  default https://localhost:9200
#   INDEXER_USER/PASS: compose defaults admin / SecretPassword
#
# Output: detection/tests/fp-report-<ts>.json + stdout verdict.
# Exit 0 iff there are zero Sentinel X alerts on normal traffic.

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && cd ../.. && pwd)"   # repo root (script lives in detection/tests/)
cd "$REPO_ROOT" || exit 2
APP_ROOT="$REPO_ROOT/supportdesk"
OUT="$(pwd)/detection/tests/fp-report-$(date -u +%Y%m%dT%H%M%S).json"

BASE="${BASE:-http://localhost:3000}"
DURATION="${DURATION:-600}"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-SecretPassword}"
TRAF_OUT="$REPO_ROOT/supportdesk/traffic-report-fp.json"  # must live under APP_ROOT: in container fallback the repo tree sits under /app, host paths are invisible

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
post() { python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('$1')))" 2>/dev/null; }

# 0. Sanity: app healthy + indexer reachable
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")" = "200" ] \
  || { echo "ABORT: app not healthy on $BASE"; exit 2; }
curl -sk -u "$INDEXER_USER:$INDEXER_PASS" "$INDEXER_URL" >/dev/null \
  || { echo "ABORT: indexer unreachable on $INDEXER_URL"; exit 2; }

T0=$(ts)
echo "=== FP measure: normal traffic from $T0 for ${DURATION}s ==="
# traffic.js is zero-dependency; on hosts without node (e.g. the demo LXC)
# TRAFFIC_CMD must wrap it in a node container, e.g.:
#   TRAFFIC_CMD="docker run --rm --network sentinelx_default -v $APP_ROOT:/app -w /app node:20-alpine node /app/scripts/traffic.js"
TRAFFIC_CMD="${TRAFFIC_CMD:-node}"
if [ "$TRAFFIC_CMD" = "node" ] && ! node -e 'process.exit(0)' >/dev/null 2>&1; then
  # node missing OR broken (half-installed) -- fall back to a node container
  TRAFFIC_CMD="docker run --rm --network sentinelx_default -v $APP_ROOT:/app -w /app node:20-alpine node /app/scripts/traffic.js"
  # inside the compose network the app is reachable by its service DNS name,
  # not the published host port -- sanity checks below keep probing $BASE (host)
  TRAFFIC_BASE="http://supportdesk:3000"
  echo "[i] host node not usable, using node:20-alpine container for traffic.js"
else
  TRAFFIC_BASE="$BASE"
fi
# --out must be a path THE TRAFFIC PROCESS can see: under the mounted repo tree
# in container mode (/app), the host path itself in node mode. Host side always
# reads $APP_ROOT/traffic-report-fp.json (same file node).
if [ "$TRAFFIC_CMD" = "node" ]; then
  TRAF_OUT_ARG="$APP_ROOT/traffic-report-fp.json"
  # host node: the script path must be given explicitly (the container
  # command above already carries /app/scripts/traffic.js)
  TRAFFIC_CMD="node $APP_ROOT/scripts/traffic.js"
else
  TRAF_OUT_ARG="/app/traffic-report-fp.json"
fi
$TRAFFIC_CMD --base "$TRAFFIC_BASE" --duration "$DURATION" --out "$TRAF_OUT_ARG"
# Integrity guard: if traffic.js produced no report, the window ran empty --
# an "OK" verdict on an empty window would be a false positive of the tool itself.
python3 - "$TRAF_OUT" <<'PYEOF'
import json, sys
try:
    t = json.load(open(sys.argv[1]))
    assert t.get("requests", 0) > 0
    assert 4 not in [int(s) // 100 for s in (t.get("byStatus") or {})]  # no 4xx: rule 100160 would fire
except Exception:
    print("ABORT: traffic report missing/empty or contains 4xx (rule 100160 would make the window dirty)")
    sys.exit(2)
PYEOF
[ $? -ne 0 ] && exit 2
T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"  # generous close (indexer flush latency)

# 1. Let the indexer flush, then aggregate the window per custom rule id
sleep 10

QUERY='{"size":0,"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"'"$T0"'","lte":"'"$T1"'"}}}]}},
"aggs":{"rules":{"terms":{"field":"rule.id","size":100},"aggs":{
"locations":{"terms":{"field":"location","size":5}},
"samples":{"top_hits":{
"size":1,"_source":["rule.description","rule.level","data","http"],
"sort":[{"timestamp":{"order":"desc"}}]}}}}}}'

RESP=$(curl -sk -u "$INDEXER_USER:$INDEXER_PASS" "$INDEXER_URL/wazuh-alerts-*/_search" \
  -H 'content-type: application/json' -d "$QUERY")
ALL_COUNT=$(curl -sk -u "$INDEXER_USER:$INDEXER_PASS" "$INDEXER_URL/wazuh-alerts-*/_count" \
  -H 'content-type: application/json' \
  -d "{\"query\":{\"bool\":{\"filter\":[{\"range\":{\"timestamp\":{\"gte\":\"$T0\",\"lte\":\"$T1\"}}}]}}}" \
  | post count)

python3 - "$T0" "$T1" "$DURATION" "$ALL_COUNT" "$TRAF_OUT" "$OUT" "$RESP" <<'PYEOF'
import json, sys
t0, t1, dur_s, all_count, traf_path, out_path, resp = sys.argv[1:8]
try:
    r = json.loads(resp)
    buckets = r.get("aggregations", {}).get("rules", {}).get("buckets", [])
except Exception as e:
    print("ABORT: bad indexer aggregation response:", e, file=sys.stderr)
    sys.exit(2)

fp_rows, native_rows = [], []
for b in buckets:
    # rule.id is a keyword in the wazuh-alerts template: bucket keys are
    # STRINGS ("100121"). Comparing them as ints silently skipped every
    # custom alert before this fix (verdict always OK).
    try:
        rid = int(b.get("key"))
    except (TypeError, ValueError):
        continue
    hits = b.get("samples", {}).get("hits", {}).get("hits", [])
    src = (hits[0].get("_source", {}) if hits else {})
    if not 100100 <= rid <= 100199:
        native_rows.append({
            "rule_id": rid,
            "count": b.get("doc_count"),
            "description": (src.get("rule") or {}).get("description", ""),
            "locations": {l.get("key"): l.get("doc_count")
                          for l in b.get("locations", {}).get("buckets", [])},
        })
        continue
    fp_rows.append({
        "rule_id": rid,
        "count": b.get("doc_count"),
        "description": (src.get("rule") or {}).get("description", ""),
        "level": (src.get("rule") or {}).get("level"),
        "sample": {"data": src.get("data"), "http": src.get("http")},
    })

try:
    traf = json.load(open(traf_path))
except Exception:
    traf = {}
fps = sum(f["count"] for f in fp_rows)
native_from_app = sum(n["locations"].get("/var/log/sentinelx/app.jsonl", 0) for n in native_rows)
requests = traf.get("requests") or 0

report = {
    "test": "W3-06 final false-positive measurement (full consolidated stack)",
    "window": {"start": t0, "end": t1, "duration_s": int(dur_s)},
    "all_wazuh_alerts_in_window": all_count,
    "sentinelx_custom_alerts_in_window": fps,
    "fp_rate": {
        # Normal-only window: every custom alert is a FP, so FP / custom alerts
        # is 0/0 (undefined) when the chain stays silent. The volume-normalised
        # figure is the meaningful one here (CONTRACT.md section 10).
        "false_positives": fps,
        "custom_alerts": fps,
        "normal_requests": requests,
        "fp_per_1000_requests": round(1000 * fps / requests, 3) if requests else None,
    },
    "native_alerts_in_window": {
        "count": sum(n["count"] for n in native_rows),
        "from_app_jsonl": native_from_app,
        "by_rule": native_rows,
    },
    "normal_traffic_performance": {
        "requests": traf.get("requests"),
        "duration_s": traf.get("duration_s"),
        "sessions": len(traf.get("sessions", [])),
        "failed_logins": len(traf.get("failedLogins", [])),
        "byStatus": traf.get("byStatus"),
        "expectedAlerts": traf.get("expectedAlerts"),
    },
    "method": ("CONTRACT.md section 10: one realistic normal-traffic session; every Sentinel X "
               "custom alert (100100-100199) inside the window is a false positive. Each alert "
               "carries its sample context for justification. Native Wazuh alerts are listed "
               "per rule and location, outside the custom-chain FP rate."),
    "false_positives": fp_rows,
    "verdict": ("FP_RATE_OK (0 Sentinel X alerts on normal traffic)" if fps == 0
                else "FP_ALERTS_FOUND - each needs justification in the qualification report"),
}
open(out_path, "w").write(json.dumps(report, indent=2, ensure_ascii=False))
print(json.dumps(report, indent=2, ensure_ascii=False))
sys.exit(0 if fps == 0 else 1)
PYEOF
RC=$?
echo "report: $OUT"
[ "$RC" = "0" ] && echo "VERDICT: FP_RATE_OK" || echo "VERDICT: FP_ALERTS_FOUND"
exit "$RC"