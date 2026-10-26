# T-009 - Rules 100120 / 100121: SQL injection

- **Date:** 20-10-2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node)
- **Contract:** CONTRACT.md v0.3.0-draft (§4.1, §8)
- **Rules tested:** 100120 (query), 100121 (body)
- **Rule file:** `detection/rules/100120_sql_injection.xml`
- **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application
- **Status:** ✅ Validated (4 out of 4 cases) - evasion limit documented

## Context

Two endpoints concatenate user input directly into an SQL query (no prepared statement):

- `GET /tickets`: the `status`, `priority`, `sort`, `dir` parameters are inserted into the `WHERE` and the `ORDER BY`. The `sort` parameter is directly injectable.
- `POST /tickets/search`: the `search` field is inserted into a `LIKE '%…%'`.

These inputs are visible in `http.request.query` and `http.request.body` (contract §4.1, validated in T-006).

## Rules tested

Two rules at the same level (10), separated to indicate **where** the pattern was seen:

```xml
<rule id="100120" level="10">
  <if_sid>100100</if_sid>
  <field name="http.request.query" type="pcre2">(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+|sleep\s*\(|benchmark\s*\(|information_schema|--\s|/\*)</field>
  <description>SupportDesk: SQL injection pattern in query string from $(source.ip)</description>
  <mitre><id>T1190</id></mitre>
  <group>web_attack,sql_injection,</group>
</rule>

<rule id="100121" level="10">
  <if_sid>100100</if_sid>
  <field name="http.request.body" type="pcre2">(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+|sleep\s*\(|benchmark\s*\(|information_schema|--\s|/\*)</field>
  <description>SupportDesk: SQL injection pattern in request body from $(source.ip)</description>
  <mitre><id>T1190</id></mitre>
  <group>web_attack,sql_injection,</group>
</rule>
```

### Design choices

- **Targeted patterns, not isolated characters**: the rule looks for combinations typical of injection (`union select`, `or 1=1`, `' or '`, `; drop`, `sleep(`, `benchmark(`, `information_schema`, comments `-- ` and `/*`), and not a simple apostrophe. A lone apostrophe is frequent in a legitimate search: including it would cause many false positives.
- **Two separate rules** to localize the injection (URL or body) in the description.
- **Case-insensitive** (`(?i)`) and whitespace-tolerant (`\s*`).

## Cases tested (`wazuh-logtest`)

| Case                      | Sample                    | Input                                                 | Expected          | Obtained        |
| ------------------------- | ------------------------- | ----------------------------------------------------- | ----------------- | --------------- |
| SQLi in the URL           | `sqli_query.jsonl`        | `sort=…) UNION SELECT username,password FROM users--` | 100120, level 10  | ✅              |
| SQLi in the body          | `sqli_body.jsonl`         | `search=xyz' OR '1'='1`                               | 100121, level 10  | ✅              |
| Normal search             | `search_normal.jsonl`     | `search=imprimante en panne`                          | no alert          | ✅ 100100 only  |
| Search with an apostrophe | `search_apostrophe.jsonl` | `search=probleme d'impression`                        | no alert          | ✅ 100100 only  |

The last case is the key false-positive test: a lone apostrophe does not trigger the rule, because the pattern requires `'` followed by `or`.

Automatic MITRE enrichment: _Initial Access_, _Exploit Public-Facing Application_.

## Indexing

```bash
cat detection/samples/sqli_query.jsonl detection/samples/sqli_body.jsonl >> detection/logs/app.jsonl
sleep 20
docker logs --since 1m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:100120&size=1" \
  | python3 -m json.tool | grep '"query"'
```

Result: no errors, and the indexed alert contains
`"query": "sort=created_at) UNION SELECT username,password FROM users--"`.

## Known limitation: encoding bypass

The rule detects keywords **in plain text**. The contract decodes the input only once (§4.1). A payload encoded one extra time (for example `%55NION` for `UNION`, or a fully URL-encoded injection) is therefore not recognized.

This is deliberately not fixed here: it is the basis of the **bonus evasion scenario** ("payload encoding"), where the bypass is shown first and the rule is then hardened (extra decoding on the application side, or patterns taking the encoded forms into account).

Other limitations:

- Signature-based detection: an injection pattern not listed goes unnoticed.
- `status` and `priority` of `/tickets` are also injectable but more constrained; not specifically targeted.
- Tested on contract-compliant samples: to be replayed with sqlmap on application V1.

## Follow-up actions

- [ ] Replay with sqlmap during the real attack (SQLi attack plan) and measure coverage.
- [ ] Evasion scenario: encoded payload, document the failure, harden the rule.
- [ ] Measure false positives on normal traffic (traffic script).