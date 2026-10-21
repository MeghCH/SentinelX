# SupportDesk — logging & events (implementation of contract §4)

**Branch:** `feat/W01-supportdesk-logging` (basis: `dev`) — 2026-10-21
**Status:** implemented + tested; the points marked "to validate" are proposals to be folded into the contract (v0.3.1) by the team.
**Suite:** `npm test` in `supportdesk/` — 20 tests `node --test`, zero extra dependency.

## What is implemented

### `middleware/logger.js`
- One event = one nested JSON line (samples shape), one JSON object per line, no pretty-print, no `url` object (D-006).
- `@timestamp` RFC3339 UTC, `trace.id` = UUID v4 per request (shared by all the event's fields).
- `source.ip` = `req.ip` (D-010 contract), `user.name` = `anonymous` when unauthenticated (sample `scan_404`).
- §4.1 sanitization: `password/pass/pwd/token/secret/session` keys masked with `***`, `cookie`/`authorization` keys removed, single `+`/`%XX` decoding, total field truncation at 512 characters with `[truncated]` marker.
- §4.3: the export/detail/comment routes stage `target.owner_id`; `target.owned_by_user` (string `true`/`false`) is computed at emission.
- 500: the global handler emits a `system` / `internal_error` / `error` event (single line guaranteed).

### Mount (deviation from the skeleton comment, to validate in the contract)
The middleware is mounted **first** (before `express.urlencoded`, static, session): only this position allows capturing the raw body before urlencoded consumes the stream; session fields remain resolvable at emission time and static/kb files remain observable.

### Catalog of events (§5)

| Action           | Route                          | Conforming sample                     | Note                                   |
| ---------------- | ------------------------------ | ------------------------------------- | -------------------------------------- |
| `login`          | `POST /login`                  | `login_failure(+body)`                | `user.name` = email tried              |
| `logout`         | `GET /logout`                  | (new — to validate)                   | identity captured before `destroy()`   |
| `search`         | `POST /tickets/search`         | `search_apostrophe` / `sqli_body`     |                                        |
| `export`         | `GET /tickets/:id/export`      | `ticket_export_own/_admin`            | `owned_by_user` computed               |
| `kb_view`        | `GET /kb/view`                 | `kb_view_traversal_success`           | payload in `query` + `target.id`       |
| `request`        | everything else                | `sqli_query` / `ssrf_*` / `scan_404`  |                                        |

`log.level`: `error` if 5xx, `warn` if 4xx or known failure (login, 403), else `info`.

## Points to validate by the team (contract addenda v0.3.1)

1. Mounted first in the chain (vs. the skeleton comment) — D-014 candidate.
2. Event action catalog + `internal_error` (500) — D-015 candidate.
3. `security.indicator: admin_area` on `/admin` and `/admin/fetch`.
4. `duration_ms` rounded to 0.1ms.
5. Requests to `/metrics` not logged (Prometheus scrape noise).
6. `better-sqlite3@^12.11.1` — the school v9.6.0 does not compile on Node 26 (C++20 headers required); the v12.11.1 has a prebuild and keeps Node 20 (the Dockerfile Docker) compatible. API (prepare/run/get/all) identical.
7. The seed accounts are `@supportdesk.local` — AP-01 must be corrected (`admin@techco.local` → `admin@supportdesk.local`) before team validation.

## Test coverage

- 7 unit tests: sanitization (masking, single decoding, forbidden keys, truncation, empty) + nested key shape/no url/one type per field.
- 13 integration tests: whole chain (login fail/success, dashboard, tickets listing, SQLi GET+POST, IDOR export, traversal kb_view, admin+SSRF+403, comment, 404 scan, unauthenticated, logout, /metrics excluded, JSON-lines integrity).
- Functional coverage of §7 endpoints: 14/15 exercised by this suite (the `/metrics` endpoint arrives next wave with the middlewares of Prometheus metrics).

## Limitations known (documented)
- Synchronous `appendFileSync` writing: acceptable for the lab + deterministic tests, to revisit in step 3 (load) if perf requires it.
- `X-Forwarded-For` spoofable on purpose (D-010, evasion scenario).