# Sentinel X — SupportDesk observable et détectable

**SupportDesk** est une application web de gestion de tickets pour une PME. Le projet la rend **observable** (métriques Prometheus, dashboards Grafana) et la **défend** par une détection temps réel des attaques (Wazuh, règles custom `100100`–`100161`). C'est le rendu Epitech **B-SPE-322 « Sentinel X »**.

Le contrat technique qui fait foi est [`CONTRACT.md`](CONTRACT.md) (v0.3.2 validée).

## Architecture

La stack complète se lance depuis le [`docker-compose.yml`](docker-compose.yml) racine. Il inclut les compose de l'application et de Wazuh, et ajoute Prometheus et Grafana.

| Composant             | Service                | Port(s) hôte                  | Rôle                                   |
| --------------------- | ---------------------- | ----------------------------- | -------------------------------------- |
| SupportDesk           | `supportdesk`          | 3000                          | Application web de tickets             |
| Prometheus            | `prometheus`           | 9090                          | Collecte des métriques                 |
| Grafana               | `grafana`              | 3001                          | Dashboards de métriques                |
| Wazuh manager         | `wazuh.manager`        | 55000 (API)                   | Analyse des logs et alertes            |
| Wazuh indexer         | `wazuh.indexer`        | 9200                          | Stockage des alertes et événements     |
| Wazuh dashboard       | `wazuh.dashboard`      | 443 → 5601                    | Interface de détection                 |
| Dashboard init        | `wazuh.dashboard-init` | —                             | Import one-shot du dashboard versionné |

Wazuh 4.14.9 tourne en single-node depuis [`detection/wazuh/docker-compose.wazuh.yml`](detection/wazuh/docker-compose.wazuh.yml). L'application écrit un JSON par ligne dans `detection/logs/app.jsonl` ; le manager le lit en lecture seule (contrat §2 et D-008).

## Démarrage rapide (clone neuf)

### Prérequis

- Docker Engine + Docker Compose **≥ 2.20** (`docker compose version`) — les chemins relatifs des fichiers `include` en dépendent.
- **8–12 Go de RAM** disponibles (l'indexer OpenSearch prend ~4 Go de heap).
- Sur un hôte Linux : `sudo sysctl -w vm.max_map_count=262144` (l'indexer refuse de démarrer en dessous).

### 1. Cloner le dépôt

```bash
git clone https://github.com/EpitechBachelorPromo2028/B-SPE-322-STG-3-1-sentinelx-2.git
cd B-SPE-322-STG-3-1-sentinelx-2
```

### 2. Générer les certificats TLS Wazuh (obligatoire sur un clone neuf)

Les certificats ne sont **pas** versionnés (`.gitignore`) : chaque clone doit générer les siens, une seule fois.

```bash
cd detection/wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
```

Le message `find: command not found` en fin de génération est sans conséquence. Vérifier que `detection/wazuh/config/wazuh_indexer_ssl_certs/` contient bien les `.pem` et `-key.pem` attendus.

> Déjà présent ? Si `detection/wazuh/config/wazuh_indexer_ssl_certs/` existe et est peuplé, **sautez cette étape**.

### 3. Démarrer toute la stack

```bash
docker compose up -d
```

Une seule commande démarre l'application, Prometheus, Grafana et Wazuh.

### 4. Attendre le premier boot Wazuh (5 à 15 min)

Le premier démarrage de Wazuh télécharge les images et initialise l'indexer. La commande rend la main quand la chaîne `indexer → manager → dashboard → dashboard-init` est saine.

```bash
docker compose ps
```

Attendu : `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` en `Up (healthy)`. Vérifier ensuite la chaîne de bout en bout :

```bash
bash detection/tests/run.sh t004
```

Attendu : **3 × `[PASS]`**. Prometheus et Grafana sont disponibles pendant le démarrage de Wazuh.

### URLs

| Service          | URL                                            | Identifiants        |
| ---------------- | ---------------------------------------------- | ------------------- |
| SupportDesk      | <http://localhost:3000>                        | voir l'application  |
| Grafana          | <http://localhost:3001>                        | `admin` / `admin`   |
| Prometheus       | <http://localhost:9090>                        | —                   |
| Wazuh dashboard  | <https://localhost>                            | `admin` / `SecretPassword` |

Le certificat Wazuh est auto-signé : accepter l'avertissement du navigateur. Le dashboard du projet est `https://localhost/app/dashboards#/view/sentinelx-detection`.

> Optionnel : copier `.env.example` vers `.env` pour surcharger les identifiants Wazuh/Grafana (le défaut du labo fonctionne sans rien faire).

### Piège connu au premier boot

Le service one-shot `wazuh.dashboard-init` (import du dashboard versionné) peut ne pas démarrer tout seul. Relancer `docker compose up -d`, ou le démarrer explicitement :

```bash
docker compose up -d wazuh.dashboard-init
docker compose logs wazuh.dashboard-init
```

Attendu dans les logs : `OK: 8 objects imported`. Vérifier ensuite que le dashboard « Sentinel X » apparaît dans l'interface Wazuh.

## Tests

### Tests de détection

13 tests de détection documentés — détail : [`docs/detection/tests/README.md`](docs/detection/tests/README.md), suite automatisée `bash detection/tests/run.sh`.

### Tests de l'application

```bash
cd supportdesk && npm test
```

Exécute la suite `node --test` (aucune dépendance supplémentaire).

## Documentation

| Sujet                                  | Document                                                              |
| -------------------------------------- | --------------------------------------------------------------------- |
| Contrat technique (référence)          | [`CONTRACT.md`](CONTRACT.md)                                          |
| Installation et usage de la détection  | [`docs/detection/setup.md`](docs/detection/setup.md) — [EN](docs/en/detection/setup.md) |
| Stack consolidée (ports, healthchecks) | [`docs/app/monitoring-stack.md`](docs/app/monitoring-stack.md)        |
| Design des logs applicatifs            | [`docs/app/logging-design.md`](docs/app/logging-design.md)            |
| Design des métriques Prometheus        | [`docs/app/metrics-design.md`](docs/app/metrics-design.md)            |
| Rapport de qualification des alertes   | [`docs/detection/alert-qualification-report.md`](docs/detection/alert-qualification-report.md) |
| Index bilingue FR ↔ EN                 | [`docs/en/README.md`](docs/en/README.md)                              |

## Convention de collaboration

Pour chaque collaboration sur ce repo Github, vous **devez** respecter cette [convention](COLLABORATION-CONVENTION.md).
Toute action ne respectant pas cette convention sera rejetée du projet.
