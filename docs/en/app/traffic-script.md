# SupportDesk — Realistic traffic script (contract §10)

**Branch:** `feat/W02-traffic-script` — 2026-10-22
**Purpose:** normal reference traffic, recorded to measure the false-positive rate on the Wazuh side.
**Script:** `supportdesk/scripts/traffic.js` — Node ≥ 20 stdlib, **zero dependency**.

## Specification §10

| Item             | Agreed value (to be validated by the team, §12)                                  |
| ---------------- | -------------------------------------------------------------------------------- |
| Target           | `supportdesk` (default `--base http://127.0.0.1:3000`, overridable)              |
| Tool             | Node stdlib (fetch) — script versioned in the repo                               |
| Duration         | **600 s** by default (`--duration N`), proposal: ≥ 10 min per FP measurement     |
| Volume           | ~700–900 requests / 10 min: 6 employees + 1 admin, think time 2–6 s              |
| Source addresses | One fixed LAN IP per identity (`10.20.0.11`–`10.20.0.20`) sent as `X-Forwarded-For` (`trust proxy`, D-010); `--sameIp` to send everything from the machine's IP |
| Normal behavior  | login → ticket/filter browsing, search with innocent vocabulary, KB, comment, profile, export of **owned** tickets, admin: `/admin`, `/admin/fetch` (public URL), export of any ticket (legal for this role) |
| Expected alerts  | **ZERO** (default configuration). Variant `--typos N`: exactly as many 100110 alerts as typos placed (`failedLogins` from the report, ≤ N), documented as reference false positives |

## Justification table (why each rule must not trigger)

| Rule                   | Why the normal traffic does not trigger it                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `100110` login failure | Default login failures = 0. Variant `--typos N`: failures **spaced at least 90 s apart** (all users combined) → one level-3 alert per placed typo |
| `100111` brute force   | 5 failures / 60 s / same IP required; with the 90 s spacing there is at most 1 failure per 60 s window, regardless of IP                          |
| `100120/121` SQLi      | The search vocabulary is self-checked against the rule's pcre2 at script startup (abort otherwise)                                                |
| `100130` SSRF          | The only `/admin/fetch` request uses `https://status.example.com/health` (public URL, like the `fetch_normal.jsonl` sample)                       |
| `100140` traversal     | `/kb/view` only requests the 3 legitimate documents from `public/kb/`                                                                             |
| `100150` IDOR          | User exports = owned tickets (map derived from `database/seed.js`); the admin is excluded by the negation on `user.role`                          |
| `100160/161` scan      | **0 4xx responses** over the full cycle → `100160` (level 4, per 4xx event) sees nothing at all                                                   |

## False-positive measurement method (§10)

```text
false-positive rate = false positives / total alerts
```

Over the agreed duration, record: the traffic volume (JSON report produced by the script) and the period, then classify each Wazuh alert (true/false positive + justification). The only alerts expected a priori are the `100110` alerts from typos in `--typos` mode (assumed FP reference). The `sourceIps` field of the report gives each identity's IP, which makes it possible to tie an alert back to the normal traffic. Scope: custom alerts `100100`-`100199`; on a purely normal window the ratio is `0 / 0` if the chain stays silent, so the result is also expressed as false positives per 1000 requests (see §1 of the [alert qualification report](../detection/alert-qualification-report.md)).

## Usage

```bash
# Standard reference traffic (10 min, 0 expected false positives)
node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600

# Variant with 2 typos (test of the brute force rule threshold)
node scripts/traffic.js --duration 600 --typos 2 --verbose

# All traffic from the machine's IP (no X-Forwarded-For)
node scripts/traffic.js --duration 600 --sameIp

# The JSON report (requests, endpoints, statuses, sessions, source IPs) is written at the end
```

## Built-in safeguards

- Anti-injection self-check of the search vocabulary at every startup (the `100120` regexes duplicated in JS).
- Internal-URL guard on `--fetchUrl` (`100130` patterns).
- Abort if the application does not respond at startup.
- Typos reserved atomically (before any `await`) and spaced at least 90 s apart: workers that start at the same time cannot fail together. If the duration does not allow placing the N typos, the report flags it.

## Notes

- The owned-tickets map reflects `database/seed.js` (42 tickets, ids 1–42); update it if the seed changes.
- No suspicious sender address: plausible browser user-agent (Chrome on Windows) on every request.
- Sessions are real (cookies): a few re-login/logout cycles per employee over the duration.
- **Expected HTTP 500s**: the search term `probleme d'impression` contains an apostrophe that breaks the intentionally injectable SQL query of `POST /tickets/search` (≈ 1 search out of 9 → 500 + `internal_error` event). It is the functional symptom of the AP-03 vulnerability (D-005), kept on purpose: it proves that a legitimate apostrophe does not trigger `100121`. No custom rule targets 5xx. Details: §6 of the [alert qualification report](../detection/alert-qualification-report.md).