## Attack Plan -- Path traversal on /kb/view

- **ID:** AP-02
- **Author:** Meghan CRESCI-HUMANN
- **Date:** 20-10-2026
- **Status:** ☐ Draft ☐ Validated by team ☐ Executed
- **Related detection:** rules 100140 / 100141 - test T-007
- **Related runbook:** `detection/runbooks/RB-02-path-traversal.md`

### Rules of engagement

Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Scenario-specific constraints:

- Read-only: only attempt to _read_ files via traversal, never write or delete.
- Target only files already present in the lab container (e.g. `/etc/hostname`, `/etc/passwd`); do not exfiltrate anything beyond proof-of-concept.
- Authenticate with a seeded test account first (the endpoint requires a session).
- Stop immediately if the application becomes unresponsive.

### Scope

- **Target endpoint:** `GET /kb/view?doc=...`
- **Injection point:** the `doc` query parameter, concatenated into a file path without sanitization.
- **Out of scope:** every other endpoint; any write action.

### Attack vectors

- Path traversal: `../` sequences in `doc` to escape the knowledge-base directory and read arbitrary files.
- Variants: backslash (`..\`), single URL-encoding (`%2e%2e`), absolute path (`/etc/passwd`).

### Tools used

- `curl` - crafted requests with traversal payloads.
- `ffuf` (optional) - fuzz the `doc` parameter with a traversal wordlist.

Example commands (final version recorded in the runbook):

```bash
# Legitimate request (baseline, must NOT alert)
curl -s -b cookies.txt "http://localhost:3000/kb/view?doc=vpn-guide.html" -o /dev/null -w "%{http_code}\n"

# Traversal attempt
curl -s -b cookies.txt "http://localhost:3000/kb/view?doc=../../etc/hostname"

# URL-encoded variant
curl -s -b cookies.txt "http://localhost:3000/kb/view?doc=%2e%2e/%2e%2e/etc/hostname"
```

### Success criteria

The detection system must generate an alert with **severity >= 7** and **rule ID 100140** within **1 minute** of launch, with the requested file visible in the alert (`target.id`).
If a traversal returns HTTP 200 (file actually read), **rule 100141 (severity 12)** must also fire.

### Stop criteria

Stop the attack when any of the following is true:

- Alert 100140 (and 100141 if the read succeeds) has been confirmed in the dashboard.
- Maximum duration reached: 5 minutes.
- A sensitive file has been proven readable (proof-of-concept obtained - no further reading needed).
- Out-of-scope impact detected.

### MITRE ATT&CK mapping

Targeted technique: **T1190 -- Exploit Public-Facing Application**
Tactic: Initial Access.

### Expected observations (for the runbook)

- Application: `kb_view` events with `../` in `http.request.query`, status 404 (file absent) or 200 (file read).
- Wazuh: rule 100140 on every traversal attempt; rule 100141 when status is 200.
- The alert description shows the source IP and the targeted path.

### Known limitations to verify during execution

- **Encoding bypass (T-007):** only `../`, `..\` and `%2e%2e` are matched. Test a double-encoded payload (`%252e%252e`) and confirm whether it evades the rule; document and harden if so.
- **Absolute path:** a `doc` value starting with `/` has no `../`. Verify whether the app reads it and whether the rule should also match absolute paths.

### Evasion variant (bonus)

Send a double-encoded payload (`%252e%252e%252f`) that survives a single URL-decode and reaches the rule as literal `%2e`. Document the detection failure, then harden (extra decode step, or a pattern covering the encoded forms).
