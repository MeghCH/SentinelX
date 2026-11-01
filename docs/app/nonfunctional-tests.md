# Non-functional tests (step 2 of the project spec) — SupportDesk

**Branch:** `feat/W03-nonfunctional` — 2026-10-27
**Objectif :** livrable du sujet — *"Non-functional tests for performance, security, and availability"* — avec scripts **zéro dépendance** versionnés + rapports JSON.

## Vu d'ensemble

| Test        | Script                                | Prérequis                          | Livrable mesuré |
| ----------- | ------------------------------------- | ---------------------------------- | ---------------- |
| Performance | `supportdesk/scripts/nf-performance.js` | app démarrée (`--base`)             | throughput req/s, latence p50/p90/p95/p99, taux d'erreur sous charge mixte |
| Sécurité    | `supportdesk/scripts/nf-security.js`  | app démarrée (`--base`)             | 8 assertions de posture (cookies, fuites stack, accès anonymes, /metrics sans PII…) |
| Disponibilité | `supportdesk/scripts/nf-availability.sh` | docker compose up (service `supportdesk`) | downtime réel d'un restart + verdict vs budget |

Chaque script : rapports JSON horodatés dans le cwd, verdict lisibles (`PERF_OK`, `SECURITY_POSTURE_OK`, `AVAILABILITY_OK`), exit code non nul si seuils cassés (utilisable en CI plus tard, bonus sujet).

## Performance (`nf-performance.js`)

- Load mixte réaliste : workers **loggés** (un login réussi au démarrage, sessions réelles), mix pondéré (list/detail/kb/view/metrics/healthz/search), 10 workers × durée `--duration 30`.
- Aucune tentative de login échouée pendant le run : les seuils de brute force Wazuh (100110, ≥ 5 échecs) ne sont pas menacés, le taux de faux positifs du trafic ne bouge pas.
- Seuil de passage (--max-errors) : **taux d'erreur ≤ 0.5 %** (4xx hors 404/302, pannes réseau), sinon exit code non nul.
- Exemple observé (VM 4 Go, voir le rapport JSON committé) : les EJS pages rendent en millisecondes ; l'app reste stable à 10 workers.

## Sécurité (`nf-security.js`)

8 assertions de posture :

| ID  | Assertion                                             | Statut attendu |
| --- | ----------------------------------------------------- | -------------- |
| S1  | Cookie `connect.sid` est `HttpOnly`                    | PASS           |
| S2  | Un login raté ne divulge pas le password (302 sans fuite)| PASS           |
| S3  | Une erreur 400 (`/kb/view` sans `doc`) est générique, sans stack trace | PASS |
| S4  | Pages protégées visibles anonymement = 302 (jamais 200) | PASS ×5       |
| S5  | Non-admin sur `/admin` = 403 **sans** la liste des users | PASS           |
| S6  | `/metrics` public (contrainte scraper) **sans** PII dans les labels | PASS (D-002) |
| S7  | Fichier KB accessible sans auth (`/kb/password-policy.html`) | **WARN** — anomalie assumée |
| S8  | `/healthz` anonyme, propre, sans internals              | PASS           |

S7 est la vulnérabilité **volontaire** de l'école (CONTRACT.md D-005 : *"The application remains intentionally vulnerable for controlled detection scenarios"*). Le test la documente et la surveille (WARN) au lieu de la réparer : on ne casse pas le terrain de jeu des runbooks.

## Disponibilité (`nf-availability.sh`)

- `docker compose restart supportdesk` via le compose racine, puis polling `/healthz` toutes les 0.5 s.
- **Budget par défaut : 60 s** de recovery (restart docker + boot node + warm SQLite ≈ 2–5 s observés).
- Rapport : `downtimeSeconds`, `recoveredWithinBudget`.

## Usage

```bash
# app up (compose consolidé ou node app.js), puis :
node scripts/nf-security.js   --base http://127.0.0.1:3000 --out report-security.json
node scripts/nf-performance.js --base http://127.0.0.1:3000 --duration 30 --concurrency 10 --out report-perf.json
BASE=http://localhost:3000 SERVICE=supportdesk ./scripts/nf-availability.sh
```

Déroulé recommandé : **security → performance → availability** (security d'abord : si une régression posture existe, la charge ne doit pas l'aggraver sans qu'on le sache).

## Résultats de la validation (2026-10-27, VM 4 Go)

Rapports JSON générés & committés dans `docs/app/nf-reports/` :

- security : verdict `SECURITY_POSTURE_OK` (7 PASS + 1 WARN documenté S7).
- performance : `PERF_OK` (0 erreur).

## Limite connue

- La mesure perf/dispo est liée à la machine hôte : toujours comparer des runs sur la même machine (cf. les seuils du doc, pas des valeurs absolues).
- nf-availability rédémarre le service embarqué : ne pas le lancer pendant une mesure de faux positifs (il remplit le dashboard d'erreurs et peut déclencher une règle de scan).