# Sentinel X - Technical Contract

**Version:** 0.1.0-draft  
**Status:** Draft for team validation  
**Application:** SupportDesk  

## 1. Scope

SupportDesk must become observable and detectable through Prometheus, Grafana and Wazuh. The application emits one JSON object per line for each relevant event and exposes Prometheus metrics through `/metrics`.

This document is a draft to validate before instrumentation begins.

## 2. Architecture

| Component | Service | Port | Network | Purpose |
|---|---|---:|---|---|
| SupportDesk | `supportdesk` | 3000 | `sentinelx` | Business web application |
| Prometheus | `prometheus` | 9090 | `sentinelx` | Metrics collection |
| Grafana | `grafana` | 3001 | `sentinelx` | Metrics dashboards |
| Wazuh manager | `wazuh-manager` | 1514/udp, 1515/tcp | `sentinelx` | Log analysis and alerts |
| Wazuh indexer | `wazuh-indexer` | 9200 | `sentinelx` | Alert and event storage |
| Wazuh dashboard | `wazuh-dashboard` | 5601 | `sentinelx` | Detection interface |

All components are connected to the `sentinelx` Docker network. The exact Wazuh deployment method must be validated against available host resources before final integration.

## 3. Environment variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | Runtime environment |
| `PORT` | `3000` | SupportDesk HTTP port |
| `SESSION_SECRET` | unset in production | Session signing secret |
| `LOG_LEVEL` | `info` | Application log level |
| `SENTINELX_LOG_FILE` | `/var/log/sentinelx/app.jsonl` | JSONL log destination |
| `PROMETHEUS_TARGET` | `supportdesk:3000` | Prometheus scrape target |
| `PROMETHEUS_SCRAPE_INTERVAL` | `15s` | Scrape interval |

Secrets must never be committed to the repository.

## 4. JSON log contract

Each event is encoded as exactly one UTF-8 JSON object followed by a newline. Timestamps use UTC and RFC 3339 format.

### Required fields

| Field | Type | Description |
|---|---|---|
| `@timestamp` | string | Event timestamp in UTC |
| `event.dataset` | string | Constant `supportdesk.application` |
| `event.kind` | string | `event` or `alert` |
| `event.category` | string | `authentication`, `web`, `database` or `system` |
| `event.action` | string | Stable action name, for example `login`, `request`, `export` |
| `event.outcome` | string | `success`, `failure` or `unknown` |
| `log.level` | string | `info`, `warn` or `error` |
| `message` | string | Human-readable message without secrets |
| `service.name` | string | Constant `supportdesk` |
| `service.version` | string | Application version |
| `trace.id` | string | Correlation identifier for the request |

### HTTP fields

| Field | Type | Description |
|---|---|---|
| `http.request.method` | string | HTTP method |
| `url.path` | string | Normalized path without query string |
| `http.response.status_code` | integer | HTTP response status |
| `http.response.duration_ms` | number | Request duration |
| `source.ip` | string | Client IP |
| `user_agent.original` | string | User-agent header |

### Application fields

| Field | Type | Description |
|---|---|---|
| `user.id` | string/integer | Authenticated user identifier when available |
| `user.name` | string | Username when available |
| `user.role` | string | Application role when available |
| `target.id` | string/integer | Ticket or document identifier when applicable |
| `target.type` | string | `ticket`, `document`, `user` or other resource type |
| `security.indicator` | string | Optional detection context |

Passwords, session secrets, cookies, authorization headers, request bodies and full query strings must never be logged.

## 5. Events to emit

At minimum, the application must emit events for:

- Successful login
- Failed login
- Logout
- Every HTTP request, excluding `/metrics` from noisy request metrics if necessary
- HTTP 4xx and 5xx responses
- Access to administrative endpoints
- Access to sensitive ticket exports
- Access to knowledge-base documents
- Suspicious input or rejected request
- Internal application errors

Failed authentication must be identified explicitly. It cannot be inferred only from the final HTTP status because SupportDesk redirects both successful and failed login flows.

## 6. Prometheus metrics contract

`GET /metrics` returns Prometheus text exposition format with content type:

```text
text/plain; version=0.0.4; charset=utf-8
```

Required metrics:

```text
supportdesk_http_requests_total{method,path,status}
supportdesk_http_request_duration_seconds{method,path}
supportdesk_http_in_flight_requests
supportdesk_auth_attempts_total{outcome}
supportdesk_app_info{version,environment}
```

Labels must remain bounded. Query strings, ticket contents, usernames and arbitrary user-controlled values must not be labels. Paths must be normalized to prevent unbounded cardinality.

## 7. Critical endpoints

The first functional test suite must cover at least:

- `GET /login`
- `POST /login`, success and failure
- `GET /logout`
- `GET /dashboard`, authenticated and unauthenticated access
- `GET /tickets`
- `POST /tickets/search`
- `GET /tickets/:id`
- `GET /tickets/:id/export`
- `GET /admin`
- `POST /admin/fetch`
- `GET /kb`
- `GET /kb/view`
- `GET /metrics`

The final endpoint map, expected responses and authentication requirements must be documented.

## 8. Wazuh integration

Wazuh must read the SupportDesk JSONL log and decode the documented fields. Custom rule identifiers use the reserved project range `100100-100199`.

Initial custom detections must target distinct patterns:

1. Repeated failed logins from the same source.
2. Suspicious access to the administrative fetch endpoint, including possible SSRF behavior.
3. Abnormal access to ticket exports or knowledge-base paths, including possible IDOR or traversal behavior.
4. Repeated 4xx responses suggesting endpoint scanning.

Each rule must specify its severity, matching fields, threshold, rationale, fixture or attack command, and expected alert.

## 9. Testing gates

Before V1 is accepted:

- The contract has been reviewed by both team members.
- JSON logs are valid and one event occupies one line.
- `/metrics` returns valid Prometheus exposition.
- Functional tests cover the critical endpoints and report their coverage rate.
- Wazuh receives at least one SupportDesk event.
- At least one custom rule produces the expected alert from test data.
- The complete dry-run chain is documented before any attack.
- Attack plans are written and approved before execution.

## 10. Traffic and false positives

A normal-traffic script must be defined before final qualification. It must specify:

- Target application
- Number and type of requests
- Execution duration
- Expected normal behavior
- Alerts that must not be generated

The false-positive rate is calculated as:

```text
false positives / total alerts
```

The observation period and traffic volume must be recorded with the result.

## 11. Decision log

- **D-001:** JSON Lines are used because they are streamable, Docker-friendly and compatible with Wazuh decoding.
- **D-002:** Metrics labels exclude arbitrary user input to avoid cardinality explosion.
- **D-003:** Custom Wazuh rules use a dedicated project ID range.
- **D-004:** Failed login events are emitted explicitly by the authentication flow.
- **D-005:** The application remains intentionally vulnerable for controlled detection scenarios; attacks must stay inside the authorized lab environment.

## 12. Open decisions for validation

- Confirm the final Wazuh deployment mode based on available RAM and CPU.
- Confirm whether logs are collected from stdout, a shared file volume, or both.
- Validate the exact list of sensitive endpoints.
- Validate the three attack scenarios before writing rules.
- Confirm the traffic duration and false-positive measurement method.
- Confirm retention and handling rules for IP addresses and user agents.
