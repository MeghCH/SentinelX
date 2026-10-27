# Monitoring — configuration Prometheus (W3-02)

**Objet :** collecte des métriques de la cible SupportDesk. Le point d'entrée est [`prometheus.yml`](prometheus.yml).

## Ce que contient le fichier

| Clé                 | Valeur par défaut        | Source                     |
| ------------------- | ------------------------ | -------------------------- |
| `scrape_interval`   | `15s`                    | CONTRACT.md §3 (`PROMETHEUS_SCRAPE_INTERVAL`) |
| `evaluation_interval` | `15s`                  | aligné sur le scrape       |
| job `supportdesk`   | `supportdesk:3000`, path `/metrics` | CONTRACT.md §3 (`PROMETHEUS_TARGET`) |

Le target est le **nom de service docker** de SupportDesk, résoluble sur le réseau du projet `sentinelx` créé par le compose consolidé (W3). Le path `/metrics` est public (aucune session requise, cf. `docs/app/metrics-design.md`).

## Vérification que le scrape fonctionne

Une fois la stack montée :

1. `curl http://localhost:9090/api/v1/targets` → le job `supportdesk` doit être en `"health": "up"`.
2. `curl http://localhost:9090/api/v1/query?query=up` → `up{job="supportdesk"} 1`.
3. Un exemple de série : `curl "http://localhost:9090/api/v1/query?query=supportdesk_http_requests_total"` renvoie les séries au format §6.

## Intégration dans le compose

Le service `prometheus` (défini dans le compose consolidé, W3-04) monte ce
fichier en lecture seule et n'expose rien de plus : la source de vérité des
métriques reste l'application (§6). Grafana (W3) se branche dessus via son
provisioning : `http://prometheus:9090`.

## Choix assumés

- **Pas de règles d'alerting Prometheus** : les alertes de détection vivent dans Wazuh (règles XML 100100–100161) ; Grafana n'affiche que des métriques, il ne duplique pas la détection.
- **Un seul job** : SupportDesk est la cible du contrat ; ajouter un job self-scrape de Prometheus n'apporte rien au sujet.
- Overrides : tout override se fait par volume (`-v custom.yml:/etc/prometheus/prometheus.yml`), le fichier du repo garde les valeurs par défaut du contrat.