# T-007 - Rules 100140 / 100141: path traversal on /kb/view

- **Date:** 20-10-2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node)
- **Contract:** CONTRACT.md v0.3.0-draft (§4.1, §8)
- **Rules tested:** 100140, 100141
- **Rule file:** `detection/rules/100140_path_traversal.xml`
- **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application
- **Status:** ✅ Validated (3 out of 3 cases)

## Context

`GET /kb/view?doc=…` builds the path of the file to read from the `doc` parameter, without checking that it stays inside the `public/kb` folder. A `../` sequence therefore allows reading files outside the knowledge base.

The request is visible in the logs through the `http.request.query` field (contract §4.1); the requested document is also carried in `target.id`.

## Rules tested

```xml
<rule id="100140" level="7">
  <if_sid>100100</if_sid>
  <field name="http.request.path">^/kb/view$</field>
  <field name="http.request.query" type="pcre2">(?i)(\.\./|\.\.\\|%2e%2e)</field>
  <description>SupportDesk: path traversal attempt on /kb/view from $(source.ip) ($(target.id))</description>
  <mitre><id>T1190</id></mitre>
  <group>web_attack,path_traversal,</group>
</rule>

<rule id="100141" level="12">
  <if_sid>100140</if_sid>
  <field name="http.response.status_code">^200$</field>
  <description>SupportDesk: successful path traversal on /kb/view from $(source.ip) ($(target.id))</description>
  <mitre><id>T1190</id></mitre>
  <group>web_attack,path_traversal,</group>
</rule>
```

### Design choices

- **Two severity levels**: an attempt (level 7) does not have the same gravity as a successful read (level 12). An HTTP 200 status means the application returned content, so the file was probably read.
- **Searched pattern**: `../`, `..\` (Windows variant) and `%2e%2e` (encoded dots, visible if the request was double-encoded, since the contract enforces a single decoding).
- **`type="pcre2"`**: standard regular expressions, more readable than Wazuh's default engine.
- **Restriction to `/kb/view`**: limits false positives on other endpoints.

## Procedure

```bash
docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# paste the three samples one after the other
```

Then end-to-end verification (indexing):

```bash
cat detection/samples/kb_view.jsonl detection/samples/kb_view_traversal_success.jsonl >> detection/logs/app.jsonl
sleep 20
docker logs --since 1m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:100141&size=1" \
  | python3 -m json.tool | grep '"query"'
```

## Results

| Case               | Sample                            | Query                    | Status | Expected         | Obtained                  |
| ------------------ | --------------------------------- | ------------------------ | ------ | ---------------- | ------------------------- |
| Failed attempt     | `kb_view.jsonl`                   | `doc=../../etc/hostname` | 404    | 100140, level 7  | ✅ 100140, level 7        |
| Successful attempt | `kb_view_traversal_success.jsonl` | `doc=../../etc/hostname` | 200    | 100141, level 12 | ✅ 100141, level 12       |
| Normal access      | `kb_view_normal.jsonl`            | `doc=vpn-guide.html`     | 200    | no alert         | ✅ 100100 only, level 0   |

Alert details:

- Description: `SupportDesk: path traversal attempt on /kb/view from 203.0.113.42 (../../etc/hostname)` - the IP and the targeted file are immediately readable.
- Automatic MITRE enrichment: _Initial Access_, _Exploit Public-Facing Application_.
- 100141 carries `mail: 'True'`: Wazuh marks level ≥ 12 alerts for immediate notification by default (no mail server is configured in the lab).

Indexing: no errors, and the 100141 alert contains `"query": "doc=../../etc/hostname"` in the indexer. **The `http.request.query` field is validated end to end** (follow-up of T-006).

<details>
<summary>Phase 3 - failed attempt</summary>

```
id: '100140'
level: '7'
description: 'SupportDesk: path traversal attempt on /kb/view from 203.0.113.42 (../../etc/hostname)'
groups: '['supportdesk', 'web_attack', 'path_traversal']'
mitre.id: '['T1190']'
mitre.tactic: '['Initial Access']'
mitre.technique: '['Exploit Public-Facing Application']'
**Alert to be generated.
```

</details>

<details>
<summary>Phase 3 - successful attempt</summary>

```
id: '100141'
level: '12'
description: 'SupportDesk: successful path traversal on /kb/view from 203.0.113.42 (../../etc/hostname)'
groups: '['supportdesk', 'web_attack', 'path_traversal']'
mail: 'True'
mitre.id: '['T1190']'
**Alert to be generated.
```

</details>

<details>
<summary>Phase 3 - normal access</summary>

```
id: '100100'
level: '0'
description: 'SupportDesk: application event'
groups: '['supportdesk']'
mail: 'False'
```

</details>

## Known limitations

- **Absolute path bypass**: a `doc` parameter starting directly with `/` does not contain `../`. Depending on how the application assembles the path, this case may or may not allow a read: to be checked during the real attack.
- **More advanced encodings** (full double encoding, Unicode variants): only the `%2e%2e` form is covered.
- **Status 200 ≠ certainty**: 100141 indicates that the application responded successfully, not the nature of the file read.
- Tests were run on contract-compliant samples: to be replayed with the real logs of application V1.

## Follow-up actions

- [ ] Replay during the real attack (path traversal attack plan) and check the edge cases above.
- [ ] Add the T-007 cases to `detection/tests/run.sh`.