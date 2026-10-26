# T-006 - New contract fields in v0.3.0

- **Date:** 19-10-2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node)
- **Contract:** CONTRACT.md v0.3.0-draft (§4.1, §4.3)
- **Rules involved:** 100100 (parent), 100110
- **Status:** ✅ Decoding validated for all three fields - indexing validated for `http.request.body`, to be confirmed for the other two

## Context

Reading the SupportDesk code showed that most attacks (SQL injection, SSRF, path traversal, stored XSS) go through query parameters and form fields, and that IDOR detection requires the resource owner. The v0.3.0 contract therefore adds:

| Field                | Intended use                                                         |
| -------------------- | -------------------------------------------------------------------- |
| `http.request.query` | path traversal (`/kb/view`), SQL injection (`/tickets`)              |
| `http.request.body`  | SQL injection (`/tickets/search`), SSRF (`/admin/fetch`), stored XSS |
| `target.owner_id`    | IDOR (`/tickets/:id/export`)                                         |

Per the contract (§9), these fields must be validated in Wazuh **before** their implementation in the application, to avoid a new indexing conflict like the one on `data.url` (T-004).

## Samples

| File                                         | Field tested                              | Expected rule triggered      |
| -------------------------------------------- | ----------------------------------------- | ---------------------------- |
| `detection/samples/login_failure_body.jsonl` | `http.request.body` (masked password)     | 100110 (level 3)             |
| `detection/samples/kb_view.jsonl`            | `http.request.query`, `target.id`         | 100100 only (level 0)        |
| `detection/samples/ticket_export.jsonl`      | `target.owner_id`, `user.id`              | 100100 only (level 0)        |

## Procedure

```bash
for f in kb_view ticket_export login_failure_body; do
  cat detection/samples/$f.jsonl >> detection/logs/app.jsonl; sleep 3
done
sleep 15

# 1. Indexing refusal?
docker logs --since 3m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"

# 2. http.request.body indexed?
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=data.http.request.body:*&size=1" \
  | python3 -m json.tool | grep -A2 '"body"'

# 3. Decoding of the other two samples
docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# paste the content of kb_view.jsonl then ticket_export.jsonl
```

## Results

| Check                        | Result                                                  |
| ---------------------------- | ------------------------------------------------------- |
| Indexing refusal             | none ✅                                                 |
| `http.request.body` indexed  | ✅ `"body": "email=admin@techco.local&password=***"`     |
| Password masking             | ✅ `password=***`                                       |
| `http.request.query` decoded | ✅ `'doc=../../etc/hostname'` (`../` characters intact)  |
| `target.id` decoded          | ✅ `'../../etc/hostname'`                               |
| `target.owner_id` decoded    | ✅ `'5'`                                                |
| `user.id` decoded            | ✅ `'3'`                                                |

Excerpt from phase 2 (`kb_view`):

```
http.request.path: '/kb/view'
http.request.query: 'doc=../../etc/hostname'
http.response.status_code: '404'
target.id: '../../etc/hostname'
target.type: 'document'
```

Excerpt from phase 2 (`ticket_export`):

```
http.request.path: '/tickets/7/export'
target.id: '7'
target.owner_id: '5'
target.type: 'ticket'
user.id: '3'
```

Both samples trigger only the parent rule `100100` (level 0): no alert is generated, so nothing is sent to the indexer. This is expected, as the traversal and IDOR rules do not exist yet.

## Finding: field comparison for IDOR

While preparing the IDOR rule, it appears that the Wazuh rule syntax allows testing the value of a field (`<field>`) and correlating several events (`same_field`, `different_field`), but **not comparing two fields of the same event** (here, `user.id` different from `target.owner_id`).

**Decision (contract D-013):** the application itself computes the `target.owned_by_user` field (`"true"` / `"false"`, as text to comply with the "one type per field" rule). The rule only has to test `target.owned_by_user = false`. The `ticket_export.jsonl` sample has been updated accordingly.

Complementary approach considered: behavioral detection of a single user exporting many different tickets within a short period.

## Conclusion

The three new fields of contract v0.3.0 are decoded correctly by the native JSON decoder, and `http.request.body` traverses the whole chain up to the indexer without conflict. The contract can be proposed to the team for implementation.

## Follow-up actions

- [ ] Confirm the indexing of `http.request.query`, `target.owner_id` and `target.owned_by_user` as soon as the traversal rules (100140-100149) and IDOR rules (100150-100159) exist.
- [ ] Replay T-006 with the logs actually produced by application V1.