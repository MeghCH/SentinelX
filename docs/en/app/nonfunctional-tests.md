# Non-functional tests (step 2 of the project spec) — SupportDesk

**Branch:** `feat/W03-nonfunctional` — 2026-10-30 (mirror of [`docs/app/nonfunctional-tests.md`](../../../docs/app/nonfunctional-tests.md), French)
**Goal:** the project-spec deliverable — *"Non-functional tests for performance, security, and availability"* — with zero-dependency versioned scripts + JSON reports.

## Overview

| Test        | Script                                | Requirement                        | Measured deliverable |
| ----------- | ------------------------------------- | ---------------------------------- | -------------------- |
| Performance | `supportdesk/scripts/nf-performance.js` | app running (`--base`)             | throughput req/s, latency p50/p90/p95/p99, error rate under mixed load |
| Security    | `supportdesk/scripts/nf-security.js`  | app running (`--base`)             | 8 posture assertions (cookies, stack leaks, anonymous access, /metrics without PII…) |
| Availability | `supportdesk/scripts/nf-availability.sh` | docker compose up (service `supportdesk`) | real downtime of a restart + verdict vs budget |

Each script: timestamped JSON reports in the cwd, readable verdicts (`PERF_OK`, `SECURITY_POSTURE_OK`, `AVAILABILITY_OK`), non-zero exit when thresholds fail (CI-ready, project bonus).

## Performance (`nf-performance.js`)

- Realistic mixed load: **logged-in** workers (one successful login at startup, real sessions), weighted mix (list/detail/kb/view/metrics/healthz/search), 10 workers × duration `--duration 30`.
- No failed login attempt during the run: Wazuh brute-force thresholds (100110, ≥ 5 failures) are untouched, so the traffic false-positive rate does not move.
- Pass threshold (`--max-errors`): **error rate ≤ 0.5%** (4xx except 404/302, network errors), otherwise non-zero exit.
- Observed sample (4 GB VM, see the committed JSON report): EJS pages render in single-digit milliseconds; the app stays stable at 10 workers.

## Security (`nf-security.js`)

8 posture assertions:

| ID  | Assertion                                             | Expected status |
| --- | ----------------------------------------------------- | --------------- |
| S1  | `connect.sid` cookie is `HttpOnly`                     | PASS            |
| S2  | A failed login leaks nothing about the password (302, no leak) | PASS |
| S3  | A 500 (`/kb/view` without `doc`) is generic, no stack trace | PASS |
| S4  | Anonymous protected pages = 302 (never 200)             | PASS ×5         |
| S5  | Non-admin on `/admin` = 403 **without** the user list   | PASS            |
| S6  | `/metrics` public (scraper constraint) **without** PII in labels | PASS (D-002) |
| S7  | KB file reachable without auth (`/kb/password-policy.html`) | **WARN** — documented anomaly |
| S8  | `/healthz` anonymous, clean, no internals                | PASS            |

S7 is the school's **deliberate** vulnerability (CONTRACT.md D-005: *"The application remains intentionally vulnerable for controlled detection scenarios"*). The test documents and surfaces it (WARN) instead of fixing it: the runbooks' playground must not break.

## Availability (`nf-availability.sh`)

- `docker compose restart supportdesk` through the root compose, then polling `/healthz` every 0.5 s.
- **Default budget: 60 s** recovery time (docker restart + node boot + warm SQLite ≈ 2–15 s observed).
- Report: `downtimeSeconds`, `recoveredWithinBudget`.

## Usage

```bash
# app up (consolidated compose or node app.js), then:
node scripts/nf-security.js    --base http://127.0.0.1:3000 --out report-security.json
node scripts/nf-performance.js --base http://127.0.0.1:3000 --duration 30 --concurrency 10 --out report-perf.json
BASE=http://localhost:3000 SERVICE=supportdesk ./scripts/nf-availability.sh
```

Recommended order: **security → performance → availability** (security first: if a posture regression exists, load should not aggravate it unnoticed).

## Validation results (2026-10-30, 4 GB VM)

JSON reports generated & committed in `docs/app/nf-reports/`:

- security: verdict `SECURITY_POSTURE_OK` (7 PASS + 1 documented WARN S7).
- performance: `PERF_OK` (0 errors).
- availability: `AVAILABILITY_OK` (14 s downtime, 60 s budget).

## Known limit

- Perf/availability measurements are host-bound: only compare runs on the same machine (thresholds are in this doc, not absolute values).
- `nf-availability.sh` restarts the embedded service: never run it during a false-positive measurement (it floods the dashboard with errors and may trip a scan rule).