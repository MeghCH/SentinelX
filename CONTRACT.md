# Sentinel X - Technical Contract

**Version:** 0.3.1
**Status:** Draft for team validation (v0.3.1 folds the implemented addenda D-014–D-017; team review at the next check-in)  
**Application:** SupportDesk

## 1. Scope

SupportDesk must become observable and detectable through Prometheus, Grafana and Wazuh. The application emits one JSON object per line for each relevant event and exposes Prometheus metrics through `/metrics`.

This document is a draft to validate before instrumentation begins.

## 2. Architecture

| Component       | Service           |                  Port | Network     | Purpose                  |
| --------------- | ----------------- | --------------------: | ----------- | ------------------------ |
| SupportDesk     | `supportdesk`     |                  3000 | `sentinelx` | Business web application |
| Prometheus      | `prometheus`      |                  9090 | `sentinelx` | Metrics collection       |
| Grafana         | `grafana`         |                  3001 | `sentinelx` | Metrics dashboards       |
| Wazuh manager   | `wazuh.manager`   | 55000 (API, internal) | `sentinelx` | Log analysis and alerts  |
| Wazuh indexer   | `wazuh.indexer`   |       9200 (internal) | `sentinelx` | Alert and event storage  |
| Wazuh dashboard | `wazuh.dashboard` |           443 -> 5601 | `sentinelx` | Detection interface      |

Wazuh 4.14.9 is deployed in single-node mode from `detection/wazuh/docker-compose.wazuh.yml`. Service names keep the official dotted form (`wazuh.manager`, …) because TLS certificates are generated for these hostnames. Ports 1514/1515 (agents) are not used: logs are read from a shared file.

## 3. Environment variables

| Variable                     | Default                        | Description              |
| ---------------------------- | ------------------------------ | ------------------------ |
| `NODE_ENV`                   | `development`                  | Runtime environment      |
| `PORT`                       | `3000`                         | SupportDesk HTTP port    |
| `SESSION_SECRET`             | unset in production            | Session signing secret   |
| `LOG_LEVEL`                  | `info`                         | Application log level    |
| `SENTINELX_LOG_FILE`         | `/var/log/sentinelx/app.jsonl` | JSONL log destination    |
| `PROMETHEUS_TARGET`          | `supportdesk:3000`             | Prometheus scrape target |
| `PROMETHEUS_SCRAPE_INTERVAL` | `15s`                          | Scrape interval          |

Secrets must never be committed to the repository.

## 4. JSON log contract

Each event is encoded as exactly one UTF-8 JSON object followed by a newline. Timestamps use UTC and RFC 3339 format.

Format rules (validated against Wazuh 4.14.9, see `docs/detection/tests/T-004`):

- **No pretty-printing.** One event = one line. Wazuh reads the file line by line: an indented object is split into invalid fragments and silently ignored.
- **No `url` object.** Wazuh's index template already maps `data.url` as a keyword; an object there is rejected by the indexer and the alert never reaches the dashboard. The request path goes in `http.request.path`.
- **One type per field.** A field must always have the same type (the indexer rejects documents whose type differs from the first one indexed).
- **Omit unknown values.** A field with no value is omitted rather than set to `null` or `""`.

### Required fields

| Field             | Type   | Description                                                  |
| ----------------- | ------ | ------------------------------------------------------------ |
| `@timestamp`      | string | Event timestamp in UTC                                       |
| `event.dataset`   | string | Constant `supportdesk.application`                           |
| `event.kind`      | string | `event` or `alert`                                           |
| `event.category`  | string | `authentication`, `web`, `database` or `system`              |
| `event.action`    | string | Stable action name, for example `login`, `request`, `export` |
| `event.outcome`   | string | `success`, `failure` or `unknown`                            |
| `log.level`       | string | `info`, `warn` or `error`                                    |
| `message`         | string | Human-readable message without secrets                       |
| `service.name`    | string | Constant `supportdesk`                                       |
| `service.version` | string | Application version                                          |
| `trace.id`        | string | Correlation identifier for the request                       |

### HTTP fields

| Field                       | Type    | Description                                                                                      |
| --------------------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `http.request.method`       | string  | HTTP method                                                                                      |
| `http.request.path`         | string  | Request path as received, without query string (route normalization applies to metrics only, §6) |
| `http.request.query`        | string  | Sanitized query string, see §4.1                                                                 |
| `http.request.body`         | string  | Sanitized form body, see §4.1                                                                    |
| `http.response.status_code` | integer | HTTP response status                                                                             |
| `http.response.duration_ms` | number  | Request duration                                                                                 |
| `source.ip`                 | string  | Client IP, see §4.2                                                                              |
| `user_agent.original`       | string  | User-agent header                                                                                |

### Application fields

| Field                  | Type   | Description                                                                                           |
| ---------------------- | ------ | ----------------------------------------------------------------------------------------------------- |
| `user.id`              | string | Authenticated user identifier when available                                                          |
| `user.name`            | string | Username when available; attempted email for authentication events                                    |
| `user.role`            | string | Application role when available                                                                       |
| `target.id`            | string | Ticket or document identifier when applicable                                                         |
| `target.type`          | string | `ticket`, `document`, `user` or other resource type                                                   |
| `target.owner_id`      | string | Identifier of the user who owns the target resource (`created_by` for tickets), see §4.3              |
| `target.owned_by_user` | string | `"true"` if `user.id` equals `target.owner_id`, otherwise `"false"`; set on ticket accesses, see §4.3 |
| `security.indicator`   | string | Optional detection context                                                                            |

### 4.1 Request input fields

Attack payloads (SQL injection, path traversal, SSRF, stored XSS) travel in query parameters and form fields. They are logged, after sanitization, in two string fields:

- `http.request.query`: query string, URL-decoded once, as `key=value&key=value`.
- `http.request.body`: form body, URL-decoded once, as `key=value&key=value`.

Sanitization rules, applied before writing the log:

1. The value of any key matching (case-insensitive) `password`, `pass`, `pwd`, `token`, `secret`, `session`, `cookie` or `authorization` is replaced with `***`.
2. Each field is truncated to 512 characters; a truncated value ends with `[truncated]`.
3. Fields are omitted when the request has no query string or no body.
4. Cookies and the `Authorization` header are never logged.

Values are logged as received (after the single URL-decode): they must not be escaped, filtered or normalized, otherwise detection rules cannot see the payload.

### 4.2 Client IP (`source.ip`)

SupportDesk sets `app.set('trust proxy', true)`: `source.ip` is `req.ip`, i.e. the left-most address of `X-Forwarded-For` when present, otherwise the socket address.

Known limitation: `X-Forwarded-For` is client-controlled and can be rotated to evade per-IP rules. Kept on purpose in the lab and documented as an evasion scenario.

### 4.3 Resource ownership (`target.owner_id`)

`GET /tickets/:id/export` performs no ownership check. Detecting an IDOR requires the requester (`user.id`) and the owner (`target.owner_id`) in the same event. The export route sets `target.type = ticket`, `target.id`, `target.owner_id` from the ticket's `created_by`, and `target.owned_by_user`. The same applies to `GET /tickets/:id`.

`target.owned_by_user` is computed by the application because Wazuh rules cannot compare two fields of the same event. It is a string (`"true"` / `"false"`), not a boolean, to respect the one-type-per-field rule.

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

Failed authentication must be identified explicitly. It cannot be inferred only from the final HTTP status because SupportDesk redirects both successful and failed login flows with HTTP 302. A failed login is a `POST /login` whose `Location` response header is `/login?error=1`; a successful one redirects to `/dashboard`.

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
- `POST /tickets/:id/comment`
- `GET /profile`, `POST /profile`
- `GET /admin`
- `POST /admin/fetch`
- `GET /kb`
- `GET /kb/view`
- `GET /metrics`
- `GET /healthz` (healthcheck: `{status, version, uptime_s, db}`, 503 if the database is down)

The final endpoint map, expected responses and authentication requirements must be documented (see `docs/detection/Endpoints.md`).

## 8. Wazuh integration

Wazuh must read the SupportDesk JSONL log and decode the documented fields. Custom rule identifiers use the reserved project range `100100-100199`.

Initial custom detections must target distinct patterns:

| Range           | Pattern                                     | Endpoint(s)                            | Fields used                                    | MITRE |
| --------------- | ------------------------------------------- | -------------------------------------- | ---------------------------------------------- | ----- |
| `100100`        | Parent rule (any SupportDesk event)         | all                                    | `service.name`                                 | —     |
| `100110-100119` | Repeated failed logins from the same source | `POST /login`                          | `event.*`, `source.ip`                         | T1110 |
| `100120-100129` | SQL injection patterns                      | `GET /tickets`, `POST /tickets/search` | `http.request.query`, `http.request.body`      | T1190 |
| `100130-100139` | SSRF via the administrative fetch           | `POST /admin/fetch`                    | `http.request.body`                            | T1190 |
| `100140-100149` | Path traversal on knowledge-base documents  | `GET /kb/view`                         | `http.request.query`, `target.id`              | T1190 |
| `100150-100159` | IDOR on ticket export                       | `GET /tickets/:id/export`              | `target.owned_by_user`, `user.id`, `target.id` | —     |
| `100160-100169` | Endpoint scanning (repeated 4xx)            | all                                    | `http.response.status_code`, `source.ip`       | T1595 |

Each rule must specify its severity, matching fields, threshold, rationale, fixture or attack command, and expected alert.

## 9. Testing gates

Before V1 is accepted:

- The contract has been reviewed by all three team members.
- JSON logs are valid and one event occupies one line.
- New log fields are validated end to end in Wazuh (decoded and indexed) before implementation.
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
- **D-006:** Logs are single-line JSON (no pretty-printing) and contain no `url` object, because indented JSON is not decoded by Wazuh and `data.url` conflicts with the Wazuh index template (keyword). Validated in T-004.
- **D-007:** Wazuh 4.14.9 single-node is used; it runs with 8 GB allocated to Docker.
- **D-008:** Logs are collected from a shared file: SupportDesk writes `/var/log/sentinelx/app.jsonl` to the `detection/logs` volume, mounted read-only in `wazuh.manager` and read with `<localfile>` in `json` format.
- **D-009:** Query strings and form bodies are logged in `http.request.query` and `http.request.body` after sanitization (§4.1). Without them, SQL injection, SSRF, path traversal and stored XSS are undetectable.
- **D-010:** `source.ip` comes from `req.ip` with `trust proxy` enabled (§4.2). The spoofable `X-Forwarded-For` is accepted in the lab and documented as an evasion vector.
- **D-011:** Ticket accesses carry `target.owner_id` so that IDOR is detectable from a single event (§4.3).
- **D-012:** Custom rule IDs are split into sub-ranges per attack pattern (§8).
- **D-013:** The application computes `target.owned_by_user` because Wazuh rules cannot compare two fields of the same event (identified while preparing T-006). IDOR is also detectable behaviorally (one user exporting many distinct tickets).
- **D-014:** Observability chain order is metrics → logger → urlencoded → static → session → routers: the metric registers BEFORE the log can write (`/metrics` is neither logged nor counted) and the logger sees every later request. The logger adds `security.indicator: admin_area` on `/admin` and `/admin/fetch` and rounds `duration_ms` to 0.1 ms.
- **D-015:** The event action catalog is closed and documented (§4.3 action column). 500 errors emit the explicit `internal_error` action via the final error handler; both login outcomes return HTTP 302, so the real outcome is staged on the event (D-004) and read by `auth_attempts_total`.
- **D-016:** `better-sqlite3` must be `^12.11.1`: the school-pinned v9.6.0 fails to compile on modern Node (C++20 headers); v12 keeps the same API (prepare/run/get/all) and ships prebuilds (validated by the 31-test suite).
- **D-017:** Non-routed requests (static misses, probes) are labeled `/unmatched` on the `path` metric label instead of one label per file — bounded cardinality (D-002) applied to the scan case.

## 12. Open decisions for validation

- Validate the exact list of sensitive endpoints.
- Validate the three attack scenarios before writing rules.
- Confirm the traffic duration and false-positive measurement method.
- Confirm retention and handling rules for IP addresses and user agents.
- Confirm indexing of `http.request.query`, `target.owner_id` and `target.owned_by_user` once the matching rules exist (T-006 follow-up).
