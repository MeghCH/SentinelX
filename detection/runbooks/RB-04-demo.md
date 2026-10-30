# Runbook RB-04 -- Live demo: end-to-end detection on the consolidated stack

**Objet :** scénario de démonstration final (livrable D-01) -- montrer, en direct et en ~10 minutes, la chaîne complète : *attaque détectée → alerte Wazuh qualifiée → Grafana voit l'application*. Reproductible à l'identique sur la stack consolidée (compose racine).

**Prérequis :**
- Stack consolidée démarrée depuis la racine du repo (`docker compose up -d`) et healthy (`docker compose ps` → `Up (healthy)` sur supportdesk/prometheus/grafana ; Wazuh opérationnel après son premier boot de 5–15 min).
- Vérification d'attaque faite par le runbook RB-01 (brute force) et RB-03 (SQL injection) -- ce runbook ne décrit pas la méthodologie d'attaque, uniquement le déroulé démo.
- Veille à ne pas croiser la mesure de faux positifs W3-06 : pas de `fp-measure.sh` en même temps.

---

## 1. État initial (l'équipe a la stack en main)

```bash
docker compose ps --format '{{.Service}} {{.Status}}'
```

Attendu -- `supportdesk`, `prometheus`, `grafana` : `Up (healthy)` ; y compris puisque le healthcheck supportdesk sonde `/healthz` (vérification DB incluse) :

```bash
curl -s http://localhost:3000/healthz
```

Grafana est déjà alimenté : http://localhost:3001 (variable `GF_ADMIN_USER`/`PASSWORD`, défaut `admin`/`admin`) → dossier "Sentinel X" → dashboard **"SupportDesk — application overview"**. Y montrer le taux d'erreur à ~0 % et le flux d'authentifications bas (trafic normal, seuils non déclenchés).

## 2. État : appli vivante, détection armée

Wazuh dashboard : https://localhost dans un navigateur (certificat self-signed assumé). Filtre par défaut conseillé : `rule.groups:supportdesk`, tri sur le timestamp -- les nouvelles alertes arrivent en tête de liste.

## 3. Attaque 1 -- Brute force (T-1110, règle 100111)

Executer le runbook RB-01 sur la cible SupportDesk (10+ tentatives de connexion échouées pour `admin@supportdesk.local` depuis une source unique, compte de thrashing légitime conservé). Exemple inline pour la démo -- **hors runbook de mesure** :

```bash
B=http://localhost:3000
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "attempt $i: %{http_code}\n" \
    -d "email=admin@supportdesk.local&password=WRONG_${i}" $B/login
done
```

## 4. Observation 1 -- l'alerte brute force est montée

Dashboard Wazuh : alerte **100111** (brute force sur login), avec l'IP source et le compte d'échecs agrégés dans l'alerte, MITRE T1110 visible dans la fiche. Temps de détection (dwell time, bonus sujet) ≈ 30 s grand max, borné par l'interval d'ingestion de l'indexer. Dans Grafana, le panneau "Auth attempts by outcome" a monté **10×** le compteur `auth_failure` d'un coup après l'attaque.

## 5. Attaque 2 -- SQL injection (T1190, règle 100121)

Executer le hook SQLi de RB-03 : `POST /tickets/search` avec la charge qualifiée et consigner l'alerte **100121**.

```bash
curl -s -o /dev/null -w "qli: %{http_code}\n" \
  -b cookies-demo.txt \
  --data 'search=%27%20OR%20%271%27%3D%271' $B/tickets/search
```

## 6. Observation 2 -- la chaîne est complète

L'alerte **100121** apparaît dans Wazuh avec le payload dans `http.request.body` (D-009) : la tentative ne casse rien côté app (200), seule la détection la voit. À montrer au jury, la fenêtre Wazuh contient :
- **100111** (brute force) **et** **100121** (SQLi) dans Wazuh, avec leur contexte (IP source, payload dans `http.request.body`) ;
- aucun faux positif sur le trafic normal du rapport W3-06 (rapports committés : `detection/tests/fp-report-<ts>.json` ; le rapport de trafic brut `traffic-report-fp-*.json` est généré à l'exécution et non versionné, cf. `.gitignore`) ;
- Grafana ne perd rien pendant l'attaque -- l'observabilité tient les seuils non-fonctionnels (p95 en millisecondes, cf. `docs/app/nf-reports/`).

## 7. Terminée -- état de fin de session

- La démo peut se rejouer à l'identique (toutes les commandes ci-dessus sont idempotentes côté app -- l'infrastructure de mesure compte les alertes par range de fenêtre).
- La trace attestée de la démo fait partie du rapport de validation de fin de projet : collecter un screenshot des deux alertes côté Wazuh et un `curl /healthz` de fin de session dans `detection/tests/`.

## Bonus -- dwell time par scénario

Pour chaque attaque ci-dessus, le délai = timestamp de la dernière tentative (tête des logs app `detection/logs/app.jsonl`) moins le timestamp de la première alerte custom 1001xx correspondant dans Wazuh. À documenter dans le rapport final (bonus sujet "measure per-scenario detection time").

## 8. Exécution de référence (2026-10-30, LXC `sentinelx` sur toast, stack consolidée)

Scène exécutée en direct avec la stack 6 services et l'indexer green :

- bruteforce : 10 tentatives → **9 × 100110 (level 3) + 1 × 100111 (level 10)** ;
- SQLi : `POST /tickets/search` authentifié → **1 × 100121** ;
- aucune autre alerte custom : la scène ne bruite pas la chaîne ;
- dwell time observé : **< 2 s** entre la requête et l'alerte indexée ;
- conclusions reportées dans la §10 du [rapport de qualification](../../docs/detection/alert-qualification-report.md).
