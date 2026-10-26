# Wazuh detection dashboard

This document describes the dashboard used to visualize and triage the SupportDesk detection alerts.

- **Tool:** Wazuh 4.14.9 - native **Threat Hunting** dashboard
- **Access:** `https://localhost` -> **Threat Hunting** menu -> **Dashboard** tab
- **Default credentials:** `admin` / `SecretPassword`

---

## 1. Base filter

All views are restricted to project alerts by the query (DQL search bar, at the top):

```
rule.groups:supportdesk
```

This filter excludes background noise (system alerts from the Wazuh manager: file integrity, configuration assessment, etc.) and keeps only the alerts produced by custom rules `100100`-`100169`.

The query is **saved** (disk icon to the left of the search bar) so it can be reapplied in one click.

---

## 2. Dashboard panels

The dashboard covers the four requested dimensions: **severity, timeline, attack type, source.**

| Panel                               | Dimension           | What it shows                                                                                                       |
| ----------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Counters (header)**               | Volume              | Total alerts, alerts at level ≥ 12 (critical), authentication failures and successes                                |
| **Top 10 Alert level evolution**    | Severity + timeline | Evolution of alert counts over time, broken down by severity level (3, 4, 7, 10, 12…)                               |
| **Top 10 MITRE ATT&CKS**            | Attack type         | Technique breakdown: _Exploit Public-Facing Application_ (SQLi, SSRF, traversal), _Password Guessing_ (brute force) |
| **Top 5 agents**                    | Source              | Alert breakdown by emitting agent                                                                                    |
| **Alerts evolution - Top 5 agents** | Source + timeline   | Alert evolution per source over time                                                                                 |

![Dashboard overview](../../detection/img/dashboard-overview.png)

---

## 3. Filter by severity

Severity is readable directly in the _Alert level evolution_ panel (legend per level). To isolate a level, add to the query:

```
rule.groups:supportdesk and rule.level >= 10
```

Reminder of the project scale:

| Level | Meaning                                                   |
| ----- | ---------------------------------------------------------- |
| 3-5   | Notable single event (a failed login, a 404)               |
| 7-9   | Suspicious behavior (traversal attempt, isolated payload)  |
| 10    | Probable attack (brute force, injection, scan)             |
| 12+   | Successful attack (e.g. a traversal that read a file)      |

---

## 4. Filter by event type

The attack type is visible via the MITRE panel. To filter on a specific application event type, add one of these criteria to the query:

```
rule.groups:supportdesk and data.event.category:authentication
rule.groups:supportdesk and data.event.action:export
rule.groups:supportdesk and data.event.action:login
```

The whole dashboard is recomputed on the filtered subset.

![Dashboard filtered on authentication](../../detection/img/dashboard-filtered-auth.png)

---

## 5. Filter by source

The source is visible via the _Top 5 agents_ panels. To filter on a specific attacker IP:

```
rule.groups:supportdesk and data.source.ip:"203.0.113.42"
```

**Note on the source IP:** in local testing, attacks launched by `curl`, `hydra` or `sqlmap` without an `X-Forwarded-For` header appear with the Docker bridge IP (`::ffff:172.18.0.1`). To distinguish multiple sources, the `X-Forwarded-For` header is used (contract §4.2) - which is also the documented evasion vector (IP rotation).

---

## 6. Table view (Events tab)

The **Events** tab complements the dashboard with an investigation table. Configured columns:

`timestamp` · `rule.description` · `rule.id` · `rule.level` · `data.source.ip` · `rule.mitre.technique`

Each row is expandable (magnifier icon on the left) to see the full detail of an alert, including the `previous_output` field, which contains the events that led to a correlation (brute force, scan).

---

## 7. Usage for alert triage

Quick procedure to triage a wave of alerts:

1. Apply the base filter `rule.groups:supportdesk`.
2. Restrict the time range (selector at the top right) around the incident.
3. Sort by descending severity (`rule.level >= 10`) to handle probable and successful attacks first.
4. For each alert, open the detail and record: `rule.id`, `data.source.ip`, and the payload (`data.http.request.query` / `body`).
5. Classify as true or false positive (see the alert qualification report, step 3).