## Attack Plan -- SQL injection on /tickets and /tickets/search

- **ID:** AP-03
- **Author:** Meghan CRESCI-HUMANN
- **Date:** 20-10-2026
- **Status:** ✅ Validated by team (2026-10-30, Will + Meghan, review + check-in) and executed: payload injection via curl + sqlmap → alerts 100120/100121; re-verified live on the consolidated stack (RB-03 and RB-04 demo)
- **Related detection:** rules 100120 / 100121 - test T-009
- **Related runbook:** `detection/runbooks/RB-03-sql-injection.md`

### Rules of engagement

Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Scenario-specific constraints:

- The database is a disposable lab SQLite instance; still, avoid destructive payloads (`DROP`, `DELETE`) beyond a single documented proof-of-concept, and snapshot/restore the DB if one is run.
- Authenticate with a seeded test account first (both endpoints require a session).
- Extract only proof-of-concept data (e.g. confirm another table is reachable); do not dump full user credentials beyond what proves the vulnerability.
- Stop immediately if the application becomes unresponsive.

### Scope

- **Target endpoints:**
  - `GET /tickets` - parameters `status`, `priority`, `sort`, `dir` concatenated into the SQL `WHERE` / `ORDER BY`.
  - `POST /tickets/search` - field `search` concatenated into a `LIKE '%...%'`.
- **Out of scope:** every other endpoint; destructive statements beyond a single controlled PoC.

### Attack vectors

- Boolean-based injection: `' OR '1'='1` in the `search` field.
- UNION-based injection: `UNION SELECT ...` via the `sort` parameter to read another table.
- Error/time-based probing (sqlmap), as a coverage test.

### Tools used

- `curl` - manual crafted payloads (baseline + PoC).
- `sqlmap` - automated detection and exploitation.

Example commands (final version recorded in the runbook):

```bash
# Legitimate search (baseline, must NOT alert)
curl -s -b cookies.txt -X POST http://localhost:3000/tickets/search -d 'search=printer'

# Boolean injection in the body
curl -s -b cookies.txt -X POST http://localhost:3000/tickets/search -d "search=xyz' OR '1'='1"

# UNION injection in the query string
curl -s -b cookies.txt "http://localhost:3000/tickets?sort=created_at)%20UNION%20SELECT%20username,password%20FROM%20users--"

# Automated
sqlmap -u "http://localhost:3000/tickets/search" --data="search=test" \
  --cookie="$(cat cookie_value)" --batch
```

### Success criteria

The detection system must generate an alert with **severity >= 10** and **rule ID 100120 or 100121** within **2 minutes** of launch, with the payload visible in the alert (`http.request.query` or `http.request.body`).

### Stop criteria

Stop the attack when any of the following is true:

- Alert 100120 or 100121 has been confirmed in the dashboard.
- Maximum duration reached: 10 minutes (sqlmap can be slow).
- Proof-of-concept obtained (data from another table retrieved).
- Out-of-scope or destructive impact detected.

### MITRE ATT&CK mapping

Targeted technique: **T1190 -- Exploit Public-Facing Application**
Tactic: Initial Access.

### Expected observations (for the runbook)

- Application: `request` / `search` events carrying the injection string in `http.request.query` or `http.request.body`.
- Wazuh: rule 100120 (query) or 100121 (body) per matching request.
- sqlmap generates many requests: expect repeated alerts, and possibly scan-like 4xx noise.

### Known limitations to verify during execution

- **Encoding bypass (T-009):** the rule matches clear-text keywords. sqlmap often encodes payloads; since the contract decodes once, a once-more-encoded payload (`%55NION`) may evade the rule. Measure sqlmap's detection rate against the rule and document gaps.
- **False positives:** confirm the normal-traffic script (searches containing apostrophes, SQL-like words) does not trigger 100120/100121 before locking the patterns.

### Evasion variant (bonus)

Run sqlmap with `--tamper` (e.g. `charencode`, `space2comment`) to encode/obfuscate the payload. Document which alerts are lost, then harden the rule (additional decode step, or patterns covering tamper forms).
