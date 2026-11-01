#!/usr/bin/env bash
# Sentinel X - rejeu automatique des tests de détection Wazuh
#
# Usage (depuis la racine du repo) :
#   ./detection/tests/run.sh            # tous les tests
#   ./detection/tests/run.sh t004       # chaîne de bout en bout
#   ./detection/tests/run.sh t005       # corrélation rafale vs espacé
#
# Variables optionnelles :
#   MANAGER=sentinelx-wazuh.manager-1  INDEXER_URL=https://localhost:9200
#   INDEXER_USER=admin  INDEXER_PASS=SecretPassword
#   (INDEXER_PASS falls back to WAZUH_INDEXER_PASSWORD, from .env/.env.example)

set -uo pipefail

MANAGER="${MANAGER:-sentinelx-wazuh.manager-1}"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-${WAZUH_INDEXER_PASSWORD:-SecretPassword}}"
SAMPLE="detection/samples/login_failure.jsonl"
LOGFILE="detection/logs/app.jsonl"
ALERTS="/var/ossec/logs/alerts/alerts.json"
WINDOW_WAIT=65      # > timeframe de la règle 100111 (60 s)
PROCESS_WAIT=15     # temps laissé à Wazuh pour traiter et indexer

PASSED=0; FAILED=0

# ---------- affichage ----------
info() { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; PASSED=$((PASSED+1)); }
ko()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }
obs()  { printf '\033[1;33m[OBS]\033[0m %s\n' "$*"; }

# ---------- mesures ----------
# Nombre d'alertes dans alerts.json correspondant à un motif
alerts_count() {
  local n
  n=$(docker exec "$MANAGER" grep -c "$1" "$ALERTS" 2>/dev/null)
  echo "${n:-0}"
}
# Nombre d'alertes réellement indexées (= visibles dans le dashboard)
indexed_count() {
  curl -sk -u "$INDEXER_USER:$INDEXER_PASS" \
    "$INDEXER_URL/wazuh-alerts-*/_count?q=$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0
}
inject() {   # inject <nombre> <pause entre lignes en secondes>
  for _ in $(seq 1 "$1"); do
    cat "$SAMPLE" >> "$LOGFILE"
    [ "$2" -gt 0 ] && sleep "$2"
  done
}
wait_window() {
  info "Attente de ${WINDOW_WAIT}s pour vider la fenêtre de corrélation…"
  sleep "$WINDOW_WAIT"
}

# ---------- prérequis ----------
preflight() {
  info "Vérification des prérequis"
  docker ps --format '{{.Names}}' | grep -qx "$MANAGER" \
    || { echo "Conteneur $MANAGER introuvable. Lance d'abord Wazuh."; exit 1; }
  [ -f "$SAMPLE" ] || { echo "Échantillon $SAMPLE introuvable."; exit 1; }
  [ "$(wc -l < "$SAMPLE")" -eq 1 ] \
    || { echo "$SAMPLE doit contenir exactement 1 ligne terminée par un retour à la ligne (pas d'indentation)."; exit 1; }
  python3 -c "import json,sys; json.loads(open(sys.argv[1]).read())" "$SAMPLE" \
    || { echo "$SAMPLE n'est pas un JSON valide."; exit 1; }
  touch "$LOGFILE"
  docker exec "$MANAGER" grep -q "Analyzing file: '/var/log/sentinelx/app.jsonl'" /var/ossec/logs/ossec.log \
    || { echo "Le manager ne surveille pas /var/log/sentinelx/app.jsonl (vérifier <localfile> et le volume)."; exit 1; }
  info "OK : conteneur actif, échantillon valide (1 ligne), fichier surveillé"
}

# ---------- T-004 ----------
t004() {
  info "=== T-004 : chaîne fichier → Wazuh → indexer ==="
  local start a0 i0 a1 i1 errors
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  a0=$(alerts_count '"supportdesk"'); i0=$(indexed_count 'rule.groups:supportdesk')

  inject 5 1
  sleep "$PROCESS_WAIT"

  a1=$(alerts_count '"supportdesk"'); i1=$(indexed_count 'rule.groups:supportdesk')
  errors=$(docker logs --since "$start" "$MANAGER" 2>&1 | grep -ciE "cannot index|mapper_parsing")

  info "Alertes générées : +$((a1-a0)) | indexées : +$((i1-i0)) | erreurs d'indexation : $errors"
  [ $((a1-a0)) -ge 5 ] && ok "T-004 : 5 alertes générées"      || ko "T-004 : alertes générées = $((a1-a0)) (attendu ≥ 5)"
  [ "$errors" -eq 0 ]  && ok "T-004 : aucune erreur d'indexation" || ko "T-004 : $errors refus d'indexation (voir docker logs)"
  [ $((i1-i0)) -ge 5 ] && ok "T-004 : alertes visibles dans l'indexer" || ko "T-004 : alertes indexées = $((i1-i0)) (attendu ≥ 5)"
}

# ---------- T-005 ----------
t005() {
  info "=== T-005 : corrélation brute force (100111) ==="
  local b0 b1

  info "Cas A : 5 échecs en rafale"
  b0=$(alerts_count '"id":"100111"')
  inject 5 0
  sleep "$PROCESS_WAIT"
  b1=$(alerts_count '"id":"100111"')
  obs "T-005 cas A (rafale) : $((b1-b0)) alerte(s) 100111 pour 5 échecs (attendu théorique 1, observé précédemment 0)"

  wait_window

  info "Cas B : 10 échecs espacés de 3 s"
  b0=$(alerts_count '"id":"100111"')
  inject 10 3
  sleep "$PROCESS_WAIT"
  b1=$(alerts_count '"id":"100111"')
  [ $((b1-b0)) -eq 2 ] && ok "T-005 cas B : 2 alertes 100111 pour 10 échecs" \
                       || ko "T-005 cas B : $((b1-b0)) alerte(s) 100111 (attendu 2)"
}

# ---------- main ----------
preflight
case "${1:-all}" in
  t004) t004 ;;
  t005) t005 ;;
  all)  t004; wait_window; t005 ;;
  *)    echo "Usage : $0 [t004|t005|all]"; exit 2 ;;
esac

echo
info "Résultat : $PASSED réussi(s), $FAILED échoué(s)  —  $(date '+%Y-%m-%d %H:%M')"
[ "$FAILED" -eq 0 ]