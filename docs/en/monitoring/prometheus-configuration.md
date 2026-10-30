# Monitoring — Prometheus configuration (W3-02)

**Purpose:** metrics collection for the SupportDesk target. The entry point is [`prometheus.yml`](../../../monitoring/prometheus.yml). Mirror of [`monitoring/README.md`](../../../monitoring/README.md) (French).

## What the file contains

| Key                 | Default                  | Source                                  |
| ------------------- | ------------------------ | ---------------------------------------- |
| `scrape_interval`   | `15s`                    | CONTRACT.md §3 (`PROMETHEUS_SCRAPE_INTERVAL`) |
| `evaluation_interval` | `15s`                  | aligned with the scrape                  |
| job `supportdesk`   | `supportdesk:3000`, path `/metrics` | CONTRACT.md §3 (`PROMETHEUS_TARGET`) |

The target is SupportDesk's **docker service name**, resolvable on the `sentinelx` project network created by the consolidated compose (W3). The `/metrics` path is public (no session required, see [`metrics-design.md`](./metrics-design.md)).

## Verifying the scrape works

Once the stack is up:

1. `curl http://localhost:9090/api/v1/targets` → the `supportdesk` job must report `"health": "up"`.
2. `curl http://localhost:9090/api/v1/query?query=up` → `up{job="supportdesk"} 1`.
3. A sample series: `curl "http://localhost:9090/api/v1/query?query=supportdesk_http_requests_total"` returns the §6-format series.

## Integration in the compose

The `prometheus` service (defined in the consolidated compose, W3-04) mounts this read-only file and exposes no more: the source of truth for metrics remains the application (§6). Grafana (W3) connects to it through its provisioning: `http://prometheus:9090`.

## Accepted choices

- **No Prometheus alerting rules**: detection alerts live in Wazuh (XML rules 100100–100161); Grafana only displays metrics, it does not duplicate detection.
- **One single job**: SupportDesk is the contract target; adding a Prometheus self-scrape job brings nothing to the project.
- Overrides: any override happens by volume mount (`-v custom.yml:/etc/prometheus/prometheus.yml`); the repo file keeps the contract defaults.