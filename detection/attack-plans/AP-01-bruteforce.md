## Attack Plan -- Brute force on /login

- **ID:** AP-01
- **Author:** Meghan CRESCI-HUMANN
- **Date:** 20-10-2026
- **Status:** ☐ Draft ☐ Validated by team ☐ Executed
- **Related detection:** rules 100110 / 100111 - tests T-002, T-003, T-005
- **Related runbook:** `detection/runbooks/RB-01-bruteforce.md`

### Rules of engagement

Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Scenario-specific constraints:

- Run only against the lab SupportDesk container, never a shared or production host.
- Use the seeded test accounts; do not attempt to brute force real personal accounts.
- Stop immediately if the application or Wazuh becomes unresponsive.
- Announce the run to the team beforehand (shared attack window) to avoid polluting a false-positive measurement in progress.

### Scope

- **Target endpoint:** `POST /login`
- **Target account:** a valid username (`admin@techco.local`) with a wrong password, to generate `auth_failure` events.
- **Out of scope:** every other endpoint; any write/delete action on tickets.

### Attack vectors

- Authentication brute force: many password attempts against a single known account from one source IP.
- Variant (evasion, optional): spread attempts across rotated `X-Forwarded-For` values to test per-IP correlation (see §Evasion).

### Tools used

- `hydra` - automated password attempts.
- `curl` - manual single requests for the dry-run and sanity checks.
- A short wordlist of ~50 passwords (lab file, not committed).

Example commands (final version recorded in the runbook):

```bash
# Single failed login (sanity check)
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:3000/login \
  -d 'email=admin@techco.local&password=wrong'

# Brute force with hydra
hydra -l admin@techco.local -P passwords.txt \
  localhost -s 3000 http-post-form \
  "/login:email=^USER^&password=^PASS^:error=1"
```

### Success criteria

The detection system must generate an alert with **severity >= 10** and **rule ID 100111** within **2 minutes** of launch, with the correct `source.ip` visible in the alert.
Secondary: each individual failure also raises rule 100110 (severity 3).

### Stop criteria

Stop the attack when any of the following is true:

- Alert 100111 has been generated and confirmed in the dashboard (nominal success).
- Maximum duration reached: 5 minutes.
- The wordlist is exhausted.
- Out-of-scope impact detected (application error, other service affected).

### MITRE ATT&CK mapping

Targeted technique: **T1110.001 -- Brute Force: Password Guessing**
Tactic: Credential Access.

### Expected observations (for the runbook)

- Application: a burst of `auth_failure` events on `/login` with HTTP 302 and `Location: /login?error=1`.
- Metrics (Grafana): `supportdesk_auth_attempts_total{outcome="failure"}` rising sharply.
- Wazuh: rule 100110 per failure, then rule 100111 once the threshold (5 failures / 60 s / same IP) is reached.

### Known limitations to verify during execution

- **Burst correlation (T-005):** hydra sends requests very fast; measure how many failures occur before the first 100111 and the detection delay. Adjust the threshold or hardening if detection lags.
- **Threshold justification:** current threshold is 5 failures in 60 s. Confirm it does not trigger on the normal-traffic script (occasional user typos) before locking it.

### Evasion variant (bonus)

Rotate `X-Forwarded-For` so each attempt appears to come from a different IP, defeating `same_field source.ip`. Document the failure to detect, then harden (e.g. correlate on targeted `user.name` instead of, or in addition to, `source.ip`).
