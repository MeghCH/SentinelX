# Alert Qualification Report

> Step 3 deliverable: measurement of the false-positive rate of the detection chain on normal traffic, and alert qualification.

- **Measurement date:** 2026-10-26
- **Author:** [your name]
- **Wazuh version:** 4.14.9 (single-node)
- **Application:** SupportDesk V1
- **Rules evaluated:** 100100-100161 (all custom rules of the project)

---

## 1. Method

The false-positive rate is measured on **normal traffic only**, with no attack at all.
Any alert generated during this window is, by definition, a false positive (there is no real attack to detect).

```text
false-positive rate = false positives / total alerts
```

Scope of the ratio: the alerts of the **project custom rules** (range `100100`-`100199`, contract §8), the only alerts the SupportDesk detection chain produces. Wazuh **native** alerts (manager SCA configuration assessment, T-012 SSH training logs, Wazuh daemons) are not about the application: they are counted separately and excluded from the ratio.

On a **normal-only** traffic window, every custom alert is a false positive: the ratio is therefore either 100% or `0 / 0` (undefined) if the chain stays silent. The result is thus expressed in two complementary ways:

- **normal window**: number of false positives relative to the traffic volume (`false positives / 1000 normal requests`, contract §10: "the observation period and traffic volume must be recorded with the result");
- **full session** (normal window + attack scene on the same stack): `false positives / total custom alerts`, each alert being classified true or false positive.

Validity conditions (contract §10): the traffic script is **frozen and reproducible** before the measurement is launched (`feat/W02-traffic-script`, version dated 2026-10-22). It is versioned in the repository (`supportdesk/scripts/traffic.js`) and produces a JSON report of the generated traffic.

---

## 2. Measurement parameters

| Item                 | Value                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------- |
| Traffic tool         | `supportdesk/scripts/traffic.js` (Node stdlib, zero dependencies)                           |
| Command              | `node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600`                       |
| Duration             | 600 s (10 min)                                                                              |
| Simulated identities | 6 users + 1 admin, distinct IPs (`10.20.0.11`-`10.20.0.20`, via `X-Forwarded-For`)          |
| Start                | 2026-10-26 14:39:13 (local) / 13:40:30 UTC (traffic)                                        |
| End                  | 2026-10-26 14:51:20 (local) / 13:50:43 UTC (traffic)                                        |

---

## 3. Generated traffic (denominator)

Source: JSON report `traffic-report-2026-10-26T13-40-30-119Z.json`.

| Metric                      | Value                     |
| --------------------------- | ------------------------- |
| Total requests              | **1062**                  |
| Distinct endpoint types     | 76                        |
| Sessions                    | 6 users + 1 admin         |
| Login failures              | 0                         |

HTTP status breakdown:

| Status | Count |
| ------ | ----- |
| 200    | 920   |
| 302    | 134   |
| 500    | 8     |

The traffic covers **all sensitive endpoints** of the detection scope: logins/logouts, ticket search (`POST /tickets/search`, 110 requests), ticket exports (many), comments, knowledge-base consultation (`GET /kb/view`, 100 requests), and administrator access (`GET /admin`, `POST /admin/fetch`).

---

## 4. Result

| Measurement                          | Before | After | Delta |
| ------------------------------------ | ------ | ----- | ----- |
| SupportDesk alerts (100100-100161)   | 0      | 0     | **0** |

**0 false positives for 1062 normal requests (0 / 1000 requests).** The `false positives / custom alerts` ratio is `0 / 0` on this window (undefined, see §1): no custom alert was produced, there is nothing to classify.

None of the 1062 legitimate requests triggered a detection alert.

---

## 5. Qualification per rule

For each rule, justification for not triggering on normal traffic:

| Rule                     | Endpoint exercised by the traffic                  | Why no false positive                                                                                                     |
| ------------------------ | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `100110/111` brute force | `POST /login` (69 requests)                        | 0 login failures in normal traffic; no trigger possible                                                                     |
| `100120/121` SQLi        | `POST /tickets/search` (110), `GET /tickets` (211) | Search vocabulary without injection patterns (self-checked by the script against the rule regex at startup)                 |
| `100130` SSRF            | `POST /admin/fetch` (12)                           | Public target URL (`https://status.example.com/health`), never an internal address                                          |
| `100140/141` traversal   | `GET /kb/view` (100)                               | Only legitimate documents from `public/kb/` are requested, never `../`                                                      |
| `100150/151` IDOR        | ticket exports (many)                              | Users export only tickets they own; the admin is excluded by the `user.role` negation                                       |
| `100160/161` scan        | all                                                | 0 4xx responses on normal traffic: the base rule (on 4xx events) sees nothing                                               |

---

## 6. Additional observations

- **8 HTTP 500 errors** were generated by normal traffic. They **are not detection false positives** (no custom rule targets 5xx). Root cause (replayed on 2026-10-31): all of them come from `POST /tickets/search` with the legitimate term `probleme d'impression` of the script vocabulary. The search concatenates the input into the SQL query (`LIKE '%...%'`, the AP-03 vulnerability): the apostrophe closes the SQL string and SQLite fails (`near "impression": syntax error`, `internal_error` event in the logs). It is therefore the **functional symptom of the intentional SQL injection** (D-005), not a load bug: it is not fixed (the application must stay vulnerable) and the term is kept in the script, because it proves that a lone apostrophe does not trigger `100121` (T-009 "apostrophe" case). Expected: about 1 search out of 9 (1 term out of 9 in the vocabulary).
- The traffic exercised ticket exports and admin accesses **without** triggering the IDOR and SSRF rules: this confirms that these rules correctly distinguish legitimate use from an attack, which is the most sensitive point in false-positive terms.

---

## 7. Context (true positives)

The counterpart of this measurement is the effective detection of real attacks, documented in the runbooks:

| Scenario                                  | Detection               | Reference |
| ----------------------------------------- | ----------------------- | --------- |
| Brute force (hydra)                       | ✅ alerts 100111        | RB-01     |
| Path traversal (curl, `/etc/passwd` leak) | ✅ alerts 100140/100141 | RB-02     |
| SQL injection (sqlmap, database dump)     | ✅ alerts 100120/100121 | RB-03     |

The chain therefore detects the attacks (confirmed true positives) **without** generating an alert on legitimate traffic (0 false positives). The thresholds are validated by this double result.

---

## 8. Conclusion

Over a 10-minute window with 1062 representative legitimate requests, the detection chain produces **0 false positives** (0 per 1000 normal requests; the per-alert ratio is undefined on a window without alerts, see §1). The thresholds of the correlation rules (brute force, scan) are therefore calibrated without over-triggering on normal traffic, while still detecting real attacks (runbooks RB-01 to RB-03).

### Reproducibility

```bash
# 1. Count the alerts before
docker exec sentinelx-wazuh.manager-1 grep -c '"supportdesk"' /var/ossec/logs/alerts/alerts.json
# 2. Run the normal traffic (10 min)
cd supportdesk && node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600
# 3. Count the alerts after
docker exec sentinelx-wazuh.manager-1 grep -c '"supportdesk"' /var/ossec/logs/alerts/alerts.json
```

### Further investigation

A script variant (`--typos N`) injects N typos spaced more than 90 s apart.
It generates exactly N `100110` alerts (level 3) but no `100111` alert: it demonstrates
that the brute-force threshold (5 failures / 60 s) is not crossed by isolated human errors.
Run it to strengthen the threshold justification if necessary.

---

## 9. Final re-measurement (W3-06) -- full consolidated stack

Re-measurement of the false-positive rate on the **final consolidated** environment (root compose: app + Prometheus + Grafana + Wazuh) after merging wave 3. Same method (§1), same traffic script.

| Item                          | Value                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| Date                          | 2026-10-30                                                                           |
| Host                          | LXC `149 sentinelx` (toast, 4 c / 12 GB), 6-service stack `Up`, indexer **green**    |
| Window                        | 600 s (12:17:15 → 12:27:23 UTC)                                                      |
| Tool                          | `detection/tests/fp-measure.sh` (traffic + indexer aggregation in the exact window)  |
| Normal traffic                | **1058 requests**, 6 sessions, **0 failed logins**, 0 suspicious payload             |
| Statuses                      | 200 ×917, 302 ×130, 500 ×11                                                          |
| Alerts in the window          | 144 (all rules, host native alerts included)                                         |
| Custom alerts 100100-100199   | **0** (see the limitation below)                                                     |
| Native alerts                 | 144, outside the scope of the ratio (§1)                                             |
| **False positives**           | **0 for 1058 normal requests** (0 / 1000 requests); window ratio `0 / 0`             |
| **Full session (§10)**        | **0 false positives / 11 custom alerts = 0%** (11 true positives from the RB-04 scene) |

Versioned report: [`fp-report-20261030T121715.json`](../../../detection/tests/fp-report-20261030T121715.json) (raw tool output, kept as is: its `interpretation` field uses the former `0/144` computation, replaced by the reading above; the raw traffic report generated at run time, `traffic-report-fp-*.json`, is not versioned: repo `.gitignore` convention, `traffic-report-*`). Script: [`detection/tests/fp-measure.sh`](../../../detection/tests/fp-measure.sh) (exit 2 if the window runs empty or reports 4xx: an OK verdict on an empty window would itself be a false positive of the tool).

The 11 HTTP 500 responses confirm the §6 observation (legitimate apostrophe in the vulnerable search, no custom rule targets 5xx).

**Native alerts (144).** They were not broken down during this run. On the history of the local development stack (16 to 31/10, 462 native alerts), they all come from `training.log` (T-012, SSH rules 5710/5712), the manager SCA module, `wazuh-monitord` and `logcollector`: **none comes from `app.jsonl`**. Since 2026-10-31, `fp-measure.sh` writes this breakdown into the report (`native_alerts_in_window`, per `rule.id` and `location`, with a `from_app_jsonl` counter).

**Limitation (lifted on 2026-10-31, see §11): the 0 of this measurement had to be reconfirmed.** The version of `fp-measure.sh` used on 2026-10-30 compared `rule.id` to an integer, whereas the indexer returns a string (`"100121"`): it ignored **every** custom alert and could only return 0 (replayed on 2026-10-31 on a local window holding 153 custom alerts: former logic 0, fixed logic 153). The script is fixed and the 600 s measurement was run again (§11): the 0 is confirmed. The `now-10m` query of §10, run right after the 30/10 window and overlapping its end, already pointed that way (only the 11 alerts of the scene).

Effective detection confirmed the same day: T-004 PASS 3/3 with the samples, and the RB-04 demo scene run live (§10).

---

## 10. Live RB-04 demo (2026-10-30, same stack)

Scene run after the measurement window (12:27:xx UTC) through the runbook [`RB-04-demo.md`](../../../detection/runbooks/RB-04-demo.md):

| Step                                                       | Execution                                   | Wazuh result (indexer, `now-10m`)                                                    |
| ---------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------ |
| Brute force (10 failed logins `admin@supportdesk.local`)   | curl ×10, 302 (verdict in the event, D-004) | `100110` ×9 (level 3, single failure) + **`100111` level 10 (aggregated brute force)** |
| SQLi (`POST /tickets/search`, payload `' OR '1'='1`)       | user login + POST, 200                      | **`100121` level 10**                                                                |
| Dwell time                                                 | request → indexed alert                     | **< 2 s** (ingestion + indexing)                                                     |

11 custom alerts in total, exactly those expected from the scene, no other: the chain detects both demo attacks without parasitic noise. The Grafana dashboard stayed fed during the whole measurement (`supportdesk` scrape up).

---

## 11. Re-measurement with the fixed tool (2026-10-31)

Re-measurement requested by the §9 limitation. Same method (§1), same traffic script (unchanged since its last commit), fixed `fp-measure.sh`: `rule.id` read as strings, native alert breakdown, and `traffic.js` called in local node mode (the former `node --base …` call omitted the script path and only worked in container mode, the one used on the 30/10 LXC).

| Item                                  | Value                                                                                                    |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Date                                  | 2026-10-31                                                                                               |
| Host                                  | development machine (8 c / 15 GB), consolidated stack rebuilt (`docker compose up -d --build`): 6 services `Up (healthy)`, `wazuh.dashboard-init` finished (exit 0) |
| Window                                | 600 s (13:45:50 → 13:55:53 UTC)                                                                          |
| Normal traffic                        | **1043 requests**, 6 sessions, **0 failed logins**                                                       |
| Statuses                              | 200 ×891, 302 ×140, 500 ×12 (all 12: search `probleme d'impression`, see §6)                             |
| Wazuh ingestion                       | logcollector: 1325 events read from `app.jsonl` since startup (including the 1255 of the window); analysisd: **0 dropped events** |
| Custom alerts 100100-100199           | **0**                                                                                                    |
| Native alerts                         | 0 (`from_app_jsonl`: 0)                                                                                  |
| **False positives**                   | **0 for 1043 normal requests (0 / 1000 requests)**                                                       |
| Positive control (right after)        | SQLi `POST /tickets/search` from `198.51.100.200` → **`100121` level 10**, indexed **1.5 s** after the request |

Versioned report: [`fp-report-20261031T134550.json`](../../../detection/tests/fp-report-20261031T134550.json).

**Reading.** This time the 0 is established by a tool able to count custom alerts (checked on 153 alerts, §9), on a window where the chain was actually live: every application event was read and analyzed without loss, and an attack sent right after the window is detected in 1.5 s. The §9 result is **confirmed: 0 false positives on normal traffic**.
