# SupportDesk — metrics & Prometheus exposition (implementation of contract §6)

**Branch:** `feat/W03-app-metrics` — 2026-10-27
**Status:** implemented + tested; the suite grows from 20 to 28 checks (`npm test` in `supportdesk/`).

## What is implemented

### Five families, exactly as §6 requires

```
supportdesk_http_requests_total{method,path,status}        counter
supportdesk_http_request_duration_seconds{method,path}     histogram
supportdesk_http_in_flight_requests                        gauge
supportdesk_auth_attempts_total{outcome}                   counter
supportdesk_app_info{version,environment}                  gauge
```

`GET /metrics` answers with the exact contract content type:
`text/plain; version=0.0.4; charset=utf-8`, and is public (the Prometheus
scraper runs without a session).

### `middleware/metrics.js` — zero dependency

No `prom-client`: the project has kept a stdlib-only discipline so far (the
logger, the tests, the traffic script all run without extra packages), and the
required exposition is small enough to hand-write safely. Trade-off documented
here in case the team later wants richer exporters (process/GC metrics) --
that is when `prom-client` would start paying for itself.

- **Counters/gauge** live in bounded `Map`s keyed by `method|path|status`.
- **Histogram**: fixed buckets in seconds `[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]`
  -- coarse on purpose: SupportDesk renders EJS pages in single-digit
  milliseconds, anything above 2.5 s is an incident. Each observation
  increments every bucket that fits it, so bucket values are already in
  Prometheus cumulative form; `+Inf`, `_sum` and `_count` are derived at
  exposition time and `_count` always equals `requests_total` for the same
  tuple.
- **`auth_attempts_total{outcome}`** reuses the logger's staging
  (`req.sentinelx.event`): the login route stages the real outcome because
  both outcomes return HTTP 302 (contract D-004). A generic status-based
  counter could not distinguish success from failure.
- **`app_info{version,environment}`**: `version` from `package.json`
  (overridable with `SENTINELX_VERSION`), `environment` from `NODE_ENV`
  (default `development`, cf. contract §3).

### Bounded cardinality (D-002)

- Request paths are **normalized to route patterns** at observation time
  (`/tickets/7` and `/tickets/123` both become `/tickets/:id`): Express hands
  us the pattern via `req.route`, which is free and exact.
- **Unrouted requests** (static assets, 404 probes like `/admin.php`) collapse
  into a single bounded `/unmatched` label instead of one label per probed
  URL -- otherwise a scanner would create unbounded cardinality, which is
  exactly what D-002 forbids.
- **No user-controlled label value anywhere**: no query strings, no
  usernames, no ticket ids (contract §6, "Labels must remain bounded").

### `/metrics` self-exclusion

The scrape request itself is excluded from every family (requests counter,
histogram, in-flight gauge) and from the JSONL log (already the case since
W01), so Prometheus polls never pollute the measurements they watch.

### Mount order

`app.use(metrics)` is the **first** middleware, before the logger: both share
the same request lifecycle. At `res.finish` the metrics middleware also reads
the staging zone the logger middleware creates, so the two observability
layers stay consistent by construction.

## Test coverage (8 new checks, suite = 28)

- exact content-type + `# TYPE` lines for the 5 families
- `app_info` version/environment
- failed/successful login deltas on `auth_attempts_total` and
  `requests_total{POST,/login,302}`
- path normalization (`/tickets/123` -> `/:id`, raw id never a label)
- `/metrics` self-exclusion
- histogram consistency (`_count` == `requests_total` == `+Inf`,
  `le="0.01"` <= `+Inf`)
- 404 collapse to `/unmatched`
- in-flight gauge back to 0 when idle
- single-valid-line exposition

## Open decision for the team (v0.3.1 addenda candidate)

- Validate `/unmatched` as the label for non-routed requests (alternative:
  one `path` label per static file, which would grow with the KB).
- Validate the bucket set; they are only meaningful with EJS-rendered pages.
- `app_info` could later carry the git SHA (would need a build step --
  out of scope for now).
