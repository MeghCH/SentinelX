# Detection environment - installation and usage

This guide lets any team member start the project's Wazuh environment and verify that it works, starting from a clone of the repo.

- **Version:** Wazuh 4.14.9, single-node deployment (manager, indexer, dashboard)
- **Origin:** files adapted from [wazuh-docker](https://github.com/wazuh/wazuh-docker) (tag `v4.14.9`, folder `single-node`)
- **Duration:** about 15 min the first time (image downloads)

All commands run **from the repo root**, unless stated otherwise.

---

## 1. Prerequisites

| Item                        | Required                               | Check                                             |
| --------------------------- | -------------------------------------- | ------------------------------------------------- |
| Docker + Docker Compose v2  | yes                                    | `docker --version && docker compose version`      |
| RAM allocated to Docker     | 8 GB recommended (6 GB minimum)        | Docker Desktop -> Settings -> Resources -> Memory |
| `vm.max_map_count`          | ≥ 262144                               | see below                                         |
| Free ports                  | 443, 9200, 55000                       | `ss -tulpn`                                       |
| Python 3                    | for the test script                    | `python3 --version`                               |

### `vm.max_map_count`

The indexer refuses to start if this value is too low.

**Docker Engine (native Linux):**

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf   # persistant
```

**Docker Desktop:** the containers run in a VM that has its own kernel. Check the value seen by the containers:

```bash
docker run --rm --privileged alpine sysctl vm.max_map_count
```

If it is lower than 262144:

```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

This setting is lost every time Docker Desktop restarts.

---

## 2. File organization

```
detection/
├── logs/                      # volume lu par Wazuh (app.jsonl, non versionné)
├── rules/                     # règles custom (un fichier par type d'attaque), montées dans le manager
│   ├── 100100_supportdesk_base.xml
│   ├── 100110_bruteforce.xml
│   └── 100140_path_traversal.xml
├── samples/                   # échantillons de logs conformes au contrat
├── tests/run.sh               # rejeu automatique des tests
└── wazuh/
    ├── dashboards/                        # versioned Wazuh dashboard (ndjson) + import script
    ├── docker-compose.wazuh.yml
    ├── generate-indexer-certs.yml
    └── config/
        ├── certs.yml
        ├── wazuh_cluster/wazuh_manager.conf   # contient le <localfile> de l'app
        ├── wazuh_dashboard/
        ├── wazuh_indexer/
        └── wazuh_indexer_ssl_certs/           # généré, jamais versionné
```

Changes compared with the official files:

- `docker-compose.wazuh.yml`: `name: sentinelx` (predictable container names) and two mounts in `wazuh.manager`:
  - `../rules` -> `/var/ossec/etc/rules` (whole folder: all `.xml` files are loaded)
  - `../logs` -> `/var/log/sentinelx` (read only)
- `docker-compose.wazuh.yml`: healthchecks on the three services, startup ordered by `depends_on: condition: service_healthy`, one-shot `wazuh.dashboard-init` service (versioned dashboard import), agent/syslog ports (1514/1515, 514/udp) not published.
- `wazuh_manager.conf`: reads `/var/log/sentinelx/app.jsonl` in `json` format.

---

## 3. First installation

### 3.1 Generate the certificates

The TLS certificates are not versioned: each member generates their own, once.

```bash
cd detection/wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
```

The `find: command not found` message at the end of execution is **harmless** (the tool is absent from the generator image). Verify the result:

```bash
sudo ls detection/wazuh/config/wazuh_indexer_ssl_certs
```

Expected: `admin.pem`, `admin-key.pem`, `root-ca.pem`, `root-ca.key`, `root-ca-manager.pem`, `root-ca-manager.key`, and a `.pem` + `-key.pem` for `wazuh.indexer`, `wazuh.manager` and `wazuh.dashboard`.

> `sudo` is required: the generator creates the files as `root`.

### 3.2 Start the stack

```bash
docker compose -f detection/wazuh/docker-compose.wazuh.yml up -d
docker compose -f detection/wazuh/docker-compose.wazuh.yml ps
```

Each service has a **healthcheck** and startup is ordered by `depends_on: condition: service_healthy`:

| Service                | Healthcheck                                                                                   | Starts after               |
| ---------------------- | --------------------------------------------------------------------------------------------- | -------------------------- |
| `wazuh.indexer`        | authenticated `_cluster/health` is `green` or `yellow`                                        | -                          |
| `wazuh.manager`        | `wazuh-analysisd`, `wazuh-logcollector`, `wazuh-db`, `wazuh-apid` and `filebeat` running      | indexer `healthy`          |
| `wazuh.dashboard`      | `/api/status`: overall state `green`                                                          | indexer + manager `healthy` |
| `wazuh.dashboard-init` | one-shot: imports the versioned dashboard then stops (exit 0)                                 | dashboard `healthy`        |

`up -d` therefore returns once the chain is ready (a few minutes on first start). Expected: `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` `Up (healthy)`; `wazuh.dashboard-init` no longer shows in `ps` (finished, see `docker compose -f detection/wazuh/docker-compose.wazuh.yml logs wazuh.dashboard-init` → `OK: 8 objects imported`).

The agent (1514/1515) and syslog (514/udp) ports are not published: no agent is enrolled, logs are read from the shared file (contract §2, D-008).

### 3.3 Access the dashboard

- URL: `https://localhost` (self-signed certificate: accept the warning)
- Default credentials: `admin` / `SecretPassword`
- Optional: copy `.env.example` to `.env` to override the Wazuh/Grafana credentials (the lab defaults work with no change).
- Project dashboard: `https://localhost/app/dashboards#/view/sentinelx-detection` (see [dashboard.md](dashboard.md))

"Wazuh dashboard server is not ready yet": wait another minute.

### 3.4 Verify that the log file is monitored

```bash
docker exec sentinelx-wazuh.manager-1 grep -i "sentinelx" /var/ossec/logs/ossec.log
```

Expected: `Analyzing file: '/var/log/sentinelx/app.jsonl'`.

### 3.5 Validate the installation

```bash
chmod +x detection/tests/run.sh
./detection/tests/run.sh t004
```

Expected: 3 `[PASS]` lines. The installation is functional.

To replay all the tests (about 3 min 30): `./detection/tests/run.sh`. Test details: [`tests/README.md`](tests/README.md).

---

## 4. Common usage

### View the project alerts

Dashboard -> **Threat Hunting** -> **Events** tab -> query:

```
rule.groups:supportdesk
```

Other useful queries: `rule.id:100111` (brute force), `rule.level >= 10`.

The `timestamp` column is the **reception** time by Wazuh, not the log's `@timestamp`.

### Simulate application events

```bash
cat detection/samples/login_failure.jsonl >> detection/logs/app.jsonl
```

Mandatory rule: **one JSON object per line**, never indented (see `CONTRACT.md` §4).

### Modify a rule

1. Edit or create the relevant file in `detection/rules/`.
2. Restart the manager to load the new version:
   ```bash
   docker restart sentinelx-wazuh.manager-1
   ```
3. Check that no loading error appears (after ~30 s):
   ```bash
   docker exec sentinelx-wazuh.manager-1 tail -n 50 /var/ossec/logs/ossec.log | grep -iE "error|critical|warning"
   ```
4. Test the rule with a sample line:
   ```bash
   docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
5. Rerun `./detection/tests/run.sh` to verify that nothing is broken.

Reserved identifier range: `100100`–`100199` (see `CONTRACT.md` §8).

### Rule file organization

One file per attack type, prefixed with the start of its identifier range (`100140_path_traversal.xml` for 100140-100149).

Wazuh loads the files **in alphabetical order**. All rules depend on the parent rule 100100: `100100_supportdesk_base.xml` must therefore remain the first file. The numeric prefix guarantees this order.

Each file contains its own `<group name="supportdesk,">…</group>` block. An identifier must appear in one file only.

A new file added in `detection/rules/` is visible immediately in the container: a `docker restart sentinelx-wazuh.manager-1` is enough to load it. Only a change to `docker-compose.wazuh.yml` requires running `docker compose … up -d` again.

### Stop / reset

```bash
# Arrêter (les données sont conservées)
docker compose -f detection/wazuh/docker-compose.wazuh.yml down

# Repartir de zéro (supprime alertes et données indexées)
docker compose -f detection/wazuh/docker-compose.wazuh.yml down -v
```

---

## 5. Diagnostics

When an expected alert does not appear in the dashboard, check in this order:

```bash
# 1. Le conteneur voit-il les lignes ? (1 ligne = 1 événement)
docker exec sentinelx-wazuh.manager-1 wc -l /var/log/sentinelx/app.jsonl

# 2. Les alertes sont-elles générées ?
docker exec sentinelx-wazuh.manager-1 grep -c "supportdesk" /var/ossec/logs/alerts/alerts.json

# 3. L'indexer les a-t-il refusées ?
docker logs --since 5m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
```

| Failing step       | Likely cause                                                                       |
| ------------------ | ---------------------------------------------------------------------------------- |
| 1: 0 lines         | incorrect mount of the `detection/logs` volume                                     |
| 1: too many lines  | indented JSON (one event split across several lines)                               |
| 2: 0 alerts        | rule not loaded, misnamed field, or invalid JSON (test with `wazuh-logtest`)       |
| 3: errors          | type conflict with the Wazuh template (e.g. `url` object, see T-004)               |

---

## 6. Known issues

| Symptom                                                                 | Cause                                                                                                             | Solution                                                                                    |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `cp: cannot stat … wazuh_indexer_ssl_certs: Permission denied`           | certificates created as `root`                                                                                    | do not copy the certificates: regenerate them (§3.1)                                        |
| `empty compose file` / `File //config.yml is empty`                      | file created empty in the editor instead of being copied                                                          | check with `find detection/wazuh -type f -empty`, copy again from wazuh-docker `v4.14.9`    |
| The manager does not start, config path is a folder                      | misnamed file (`wazuh-manager.conf` instead of `wazuh_manager.conf`): Docker creates an empty folder instead       | rename with an underscore                                                                   |
| The indexer stops at startup                                             | `vm.max_map_count` too low or insufficient RAM                                                                    | §1                                                                                          |
| Alerts in `alerts.json` but not in the dashboard                         | indexing rejected (mapping conflict)                                                                              | §5, step 3                                                                                  |
| `alerts.json` empty the next day                                         | Wazuh archives this file every night                                                                              | normal: the history remains in the dashboard                                                |
| The brute force rule 100111 does not trigger for a burst of failures     | correlation is unreliable when events arrive grouped                                                              | known limitation, see T-005                                                                 |
| Port 443 already in use                                                  | another local service                                                                                             | change `443:5601` in the compose file (e.g. `8443:5601`)                                    |
| Error at manager startup mentioning an unknown `if_sid`                  | a rule file is loaded before the parent rule's file                                                               | check the numeric prefixes of the files (§4)                                                |
| Rule reported as duplicate at startup                                    | same identifier in two files (e.g. an old `local_rules.xml` left in place)                                        | remove the duplicate                                                                        |

- editing wazuh_manager.conf requires recreating the container (up -d --force-recreate), not a simple docker restart.

---

## 7. Security

- The default credentials (`admin` / `SecretPassword`, API passwords) are those of wazuh-docker: acceptable in a local lab, **to be changed** for any exposure outside the machine.
- The certificates (`wazuh_indexer_ssl_certs/`) and the `.env` file are excluded from Git by `.gitignore`. Verify before each push:
  ```bash
  git ls-files | grep -E "\.pem|\.key"     # ne doit rien afficher
  ```