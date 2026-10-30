#!/usr/bin/env bash
# SupportDesk -- non-functional AVAILABILITY test (step 2 deliverable).
#
# Restarts the SupportDesk service (docker compose) and measures how long the
# app takes to answer again on the health endpoint. Zero dependency.
#
# Usage (with the consolidated or test compose up):
#   BASE=http://localhost:3000 SERVICE=supportdesk ./scripts/nf-availability.sh
# On a dev machine whose host port 3000 is busy, override it with the
# !override technique (see docs/app/monitoring-stack.md) and pass BASE.
#
# Writes nf-availability-report-<ts>.json next to the cwd. Exits 0 if the
# app recovered within --budget seconds.

set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
SERVICE="${SERVICE:-supportdesk}"
BUDGET="${BUDGET:-60}"       # seconds of recovery allowed
WAIT_AFTER_DOWN="${WAIT_AFTER_DOWN:-3}"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUT="nf-availability-report-$(date -u +%Y%m%dT%H%M%S).json"

echo "Probing ${BASE} before restart..."
BEFORE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz")
if [ "$BEFORE" != "200" ]; then
  echo "ABORT: app not healthy before restart (healthz=${BEFORE})"
  exit 1
fi

echo "Stopping ${SERVICE} (compose)..."
DOWN_AT=$(date +%s)
docker compose restart "${SERVICE}" >/dev/null 2>&1 || docker compose restart -t 1 "${SERVICE}" >/dev/null 2>&1
echo "Down at ${DOWN_AT} (${WAIT_AFTER_DOWN}s settle)"
sleep "${WAIT_AFTER_DOWN}"

echo "Polling ${BASE}/healthz until recovery..."
RECOVERED_AT=""
CODE=""
for i in $(seq 1 $((BUDGET * 2))); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" || true)
  if [ "$CODE" = "200" ]; then
    RECOVERED_AT=$(date +%s)
    break
  fi
  sleep 0.5
done

if [ -z "$RECOVERED_AT" ]; then
  echo "❌ app did NOT recover within ${BUDGET}s (last code ${CODE})"
  printf '{"started": "%s", "service": "%s", "before": %s, "recovered": false, "lastCode": "%s"}\n' \
    "$TS" "$SERVICE" "$BEFORE" "${CODE:-none}" > "$OUT"
  exit 1
fi

DOWNTIME=$((RECOVERED_AT - DOWN_AT))

printf '{"started": "%s", "finished": "%s", "service": "%s", "appUrl": "%s", "budgetSeconds": %s, "downtimeSeconds": %s, "recoveredWithinBudget": %s, "healthzCode": "%s"}\n' \
  "$TS" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$SERVICE" "$BASE" "$BUDGET" "$DOWNTIME" \
  "$([ "$DOWNTIME" -le "$BUDGET" ] && echo true || echo false)" "200" > "$OUT"

echo "report: $OUT"
if [ "$DOWNTIME" -le "$BUDGET" ]; then
  echo "VERDICT: AVAILABILITY_OK (budget ${BUDGET}s)"
else
  echo "VERDICT: SLOW_RECOVERY"
  exit 1
fi