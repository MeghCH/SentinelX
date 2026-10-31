# Monitoring — Sentinel X consolidated stack (W3-04)

**Purpose:** the root compose [`docker-compose.yml`](../../../docker-compose.yml) assembles the four components of the project in one command. This document defines what runs, where, and how to verify. Mirror of [`docs/app/monitoring-stack.md`](./monitoring-stack.md) (French).

## What runs (one command)

```bash
docker compose up -d          # from the repository root
```

| Component    | Host port(s)              | Origin                                   |
| ------------ | ------------------------- | ---------------------------------------- |
| SupportDesk  | 3000                      | `supportdesk/docker-compose.yml` (included) |
| Wazuh        | 443 (dashboard), 9200 (indexer), 55000 (API) | `detection/wazuh/docker-compose.wazuh.yml` (included) |
| Prometheus   | 9090                      | this compose                             |
| Grafana      | 3001 (admin/admin by default, overridable via `GF_ADMIN_USER`/`GF_ADMIN_PASSWORD`) | this compose |

## How it is stitched together

- **`include`**: the app and Wazuh compose files remain the source of truth for their services; the root compose only adds Prometheus and Grafana. All three share the **same `sentinelx` project** → same network, so the DNS names `supportdesk`, `prometheus`, `wazuh.*` resolve each other. Relative paths of included files resolve from their own location (docker compose ≥ 2.20 required).
- **Prometheus** scrapes `supportdesk:3000/metrics` every 15 s ([monitoring](../monitoring/prometheus-configuration.md), contract §3) — see [`metrics-design.md`](../../app/metrics-design.md) for the 5 metric families format.
- **Grafana** is pre-provisioned: datasource `Prometheus` (uid `prometheus`) + dashboard "SupportDesk — application overview" (8 panels: rate, p95, error rate, statuses, auth attempts, in-flight, mean latency, app info).
- **Logs → Wazuh** unchanged: the app writes `detection/logs/app.jsonl` (bind volume, D-008) that `wazuh.manager` reads read-only.
- **No Prometheus/Grafana alerting rules**: detection is Wazuh's job (XML rules 100100–100161); Grafana observes, it does not detect.
- **Explicit healthchecks** (bonus): SupportDesk probes `/healthz` with node (`fetch`), Prometheus probes `/-/healthy` (`wget`), Grafana probes `/api/health` (`wget`) and depends on Prometheus being healthy (`depends_on` + `condition`). On the Wazuh side, the indexer probes `_cluster/health`, the manager its daemons (`analysisd`, `logcollector`, `db`, `apid`) + `filebeat`, the dashboard `/api/status`, chained indexer → manager → dashboard → `wazuh.dashboard-init` with `service_healthy` (details: [setup.md §3.2](../detection/setup.md)). `up -d` returns once the Wazuh dashboard is ready and its versioned dashboard imported.

## Post-boot verification checklist

1. App: `curl http://localhost:3000/healthz` → `{"status":"ok","db":"up",...}` (503 + `"degraded"` if the database is down).
2. Prometheus: `curl http://localhost:9090/api/v1/targets` → `supportdesk` job `"health": "up"`.
3. Grafana: http://localhost:3001 (admin/admin) → "Sentinel X" folder → "SupportDesk — application overview" populated.
4. Wazuh: https://localhost/app/dashboards#/view/sentinelx-detection (versioned dashboard, imported by `wazuh.dashboard-init`); the e2e alert is validated by the detection-side tests T-004/T-013.

## Known limitations (accepted)

- **RAM**: 8–12 GB required overall (OpenSearch ~4 GB heap). The light trio (app + Prometheus + Grafana) runs on ~1 GB and was validated standalone on a 4 GB machine.
- **Wazuh takes 5–15 min on first boot**: Prometheus/Grafana are independent and run while Wazuh starts.
- **Grafana security**: default credentials `admin/admin` (lab); override via the never-committed `.env` (repo rule).
- **No long retention**: named volumes of the Wazuh compose by default; archiving/retention is not a project deliverable.