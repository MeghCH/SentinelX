#!/usr/bin/env bash
# Sentinel X -- imports the versioned Wazuh dashboard objects
# (sentinelx-saved-objects.ndjson) into the Wazuh dashboard.
#
# Run automatically by the one-shot `wazuh.dashboard-init` service of
# detection/wazuh/docker-compose.wazuh.yml once `wazuh.dashboard` is healthy,
# or by hand from the host after editing the dashboard:
#
#   ./detection/wazuh/dashboards/import-saved-objects.sh
#
# Objects: saved query `supportdesk`, filter controls (severity, event type,
# rule, source), timeline by severity, alerts by event type, top source IPs,
# alerts by rule, latest-alerts table, and the dashboard
# "Sentinel X - Détection SupportDesk" (id sentinelx-detection).
# The import overwrites these ids only; nothing else is touched.
#
# Env:
#   DASHBOARD_URL       default https://localhost (host port 443)
#   DASHBOARD_USER/PASSWORD  compose defaults admin / SecretPassword
#   WAIT_S              max wait for the dashboard to turn green (default 600)

set -euo pipefail

URL="${DASHBOARD_URL:-https://localhost}"
AUTH="${DASHBOARD_USER:-admin}:${DASHBOARD_PASSWORD:-SecretPassword}"
FILE="${1:-$(dirname "$0")/sentinelx-saved-objects.ndjson}"
WAIT_S="${WAIT_S:-600}"
INDEX_PATTERN="wazuh-alerts-*"

[ -r "$FILE" ] || { echo "ABORT: $FILE not readable"; exit 2; }

# 1. Wait for the dashboard API (green = plugins loaded, indexer reachable).
waited=0
until curl -sk -u "$AUTH" "$URL/api/status" | grep -q '"overall":{[^}]*"state":"green"'; do
  [ "$waited" -ge "$WAIT_S" ] && { echo "ABORT: dashboard not green after ${WAIT_S}s on $URL"; exit 2; }
  sleep 10; waited=$((waited + 10))
done

# 2. Every visualization references the `wazuh-alerts-*` index pattern. The
#    Wazuh app creates it on first UI load; on a fresh stack it may not exist
#    yet, so create a minimal one (fields are fetched on first use).
code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" \
  "$URL/api/saved_objects/index-pattern/$INDEX_PATTERN")
if [ "$code" = "404" ]; then
  curl -sk -f -o /dev/null -u "$AUTH" -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -X POST "$URL/api/saved_objects/index-pattern/$INDEX_PATTERN" \
    -d "{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"timestamp\"}}"
  echo "index pattern $INDEX_PATTERN created"
fi

# 3. Import (overwrite = the repo file is the source of truth).
resp=$(curl -sk -u "$AUTH" -H 'osd-xsrf: true' -F "file=@$FILE" \
  "$URL/api/saved_objects/_import?overwrite=true")
if echo "$resp" | grep -q '"success":true'; then
  echo "OK: $(echo "$resp" | grep -o '"successCount":[0-9]*' | cut -d: -f2) objects imported -> $URL/app/dashboards#/view/sentinelx-detection"
else
  echo "FAIL: $resp"; exit 1
fi
