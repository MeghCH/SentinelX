# Monitoring — stack consolidée Sentinel X (W3-04)

**Objet :** le compose racine [`docker-compose.yml`](../../docker-compose.yml) assemble les quatre composants du sujet en une seule commande. Ce doc définit ce qui tourne, où, et comment vérifier.

## Ce qui tourne (une commande)

```bash
docker compose up -d          # depuis la racine du repo
```

| Composant    | Port(s) hôte              | Origine                                 |
| ------------ | ------------------------- | --------------------------------------- |
| SupportDesk  | 3000                      | `supportdesk/docker-compose.yml` (inclus) |
| Wazuh        | 443 (dashboard), 9200, 55000, 1514/1515, 514/udp | `detection/wazuh/docker-compose.wazuh.yml` (inclus) |
| Prometheus   | 9090                      | ce compose                               |
| Grafana      | 3001 (admin/admin par défaut, surchargeable via `GF_ADMIN_USER`/`GF_ADMIN_PASSWORD`) | ce compose |

## Comment c'est cousu

- **`include`** : les compose de l'app et de Wazuh restent la source de vérité de leurs services ; le compose racine n'ajoute que Prometheus et Grafana. Les trois partagent le **même projet `sentinelx`** → même réseau, donc les noms DNS `supportdesk`, `prometheus`, `wazuh.*` se résolvent mutuellement. Les chemins relatifs des fichiers inclus sont résolus depuis leur propre emplacement (docker compose ≥ 2.20 requis).
- **Prometheus** scrapes `supportdesk:3000/metrics` toutes les 15 s ([`monitoring/prometheus.yml`](../monitoring/README.md), contrat §3) — cf. [`docs/app/metrics-design.md`](metrics-design.md) pour le format des 5 familles.
- **Grafana** est pré-provisioné : datasource `Prometheus` (uid `prometheus`) + dashboard "SupportDesk — application overview" (8 panneaux : rate, p95, taux d'erreurs, statuts, auth attempts, in-flight, latence moyenne, app info).
- **Logs → Wazuh** inchangé : l'app écrit `detection/logs/app.jsonl` (bind volume, D-008) que `wazuh.manager` lit en lecture seule.
- **Pas de règles d'alerting Prometheus/Grafana** : la détection est le job de Wazuh (règles XML 100100–100161) ; Grafana observe, il ne détecte pas.

## Checklist de vérification après boot

1. App : `curl http://localhost:3000/metrics` → exposition §6.
2. Prometheus : `curl http://localhost:9090/api/v1/targets` → job `supportdesk` en `"health": "up"`.
3. Grafana : http://localhost:3001 (admin/admin) → dossier "Sentinel X" → "SupportDesk — application overview" alimenté.
4. Wazuh : https://localhost (dashboard) après les 5-15 min de premier démarrage ; l'alerte e2e est validée par les tests T-004/T-013 côté détection.

## Limitations connues (assumées)

- **RAM** : 8–12 Go requis au total (OpenSearch ~4 Go heap). Le trio léger (app + Prometheus + Grafana) tourne sur ~1 Go et a été validé seul sur machine 4 Go.
- **Wazuh 5–15 min au premier boot** : Prometheus/Grafana sont indépendants et fonctionnent pendant que Wazuh démarre.
- **Healthchecks/depends_on** explicités plus tard : la task junior `feat/W03-healthz` ajoute `/healthz`, le healthcheck de l'app passera de `/metrics` à `/healthz` à sa merge (bonus sujet).
- **Sécurité Grafana** : identifiants par défaut `admin/admin` (lab) ; surcharge par variables au `.env` jamais commité (règle repo).
- **Pas de rétention longue** : volumes nommés par défaut du compose Wazuh ; l'archivage/retention n'est pas un livrable du sujet.