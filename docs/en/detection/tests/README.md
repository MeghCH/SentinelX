# Detection tests

| ID | Test | Rule(s) | Result | Date |
| -------------------------------------------- | ---------------------------------------------------------------------- | -------------------- | -------------------------------------------- | ---------- | --- | ---------- | --- | ---------- |
| [T-001](T-001-json-decoder-compat.md) | Schema compatibility with the native JSON decoder | 1002 (native) | ✅ | 2026-10-15 |
| [T-002](T-002-rule-100110-login-failure.md) | Single login failure | 100100, 100110 | ✅ | 2026-10-15 |
| [T-003](T-003-rule-100111-bruteforce.md) | Per-IP brute force on /login (wazuh-logtest) | 100110, 100111 | ✅ (provisional threshold) | 2026-10-15 |
| [T-004](T-004-end-to-end-chain.md) | File → Wazuh → dashboard chain | 100100, 100110 | ✅ after 2 log format fixes | 2026-10-16 |
| [T-005](T-005-correlation-burst.md) | Brute force correlation: burst vs spaced | 100110, 100111 | ⚠️ limitation identified | 2026-10-16 |
| [T-006](T-006-new-contract-fields.md) | New contract v0.3.0 fields (query, body, owner) | 100100, 100110 | ✅ (indexing completed by T-007 and T-008) | 2026-10-19 |
| [T-007](T-007-rule-100140-path-traversal.md) | Path traversal on /kb/view (attempt, success, normal case) | 100140, 100141 | ✅ | 2026-10-19 |
| [T-008](T-008-rule-100150-idor.md) | IDOR on ticket export (isolated access, enumeration, legitimate cases) | 100150, 100151 | ✅ | 2026-10-20 |
| [T-009](T-009-rule-100120-sql-injection.md) | SQL injection (URL, body, normal search, apostrophe) | 100120, 100121 | ✅ | 2026-10-20 |
| [T-010](T-010-rule-100130-ssrf.md) | SSRF on /admin/fetch (metadata, localhost, external fetch) | 100130 | ✅ | 2026-10-20 |
| [T-011](T-011-rule-100160-scan.md) | Endpoint scanning (single 404, burst of 4xx) | 100160, 100161 | ✅ | 2026-10-20 |
| [T-012](T-012-native-rules-training-logs.md) | Native Wazuh rules on SSH training logs (secrepo) | 5710, 5712 (native) | ✅ | 2026-10-20 |
| [T-013](T-013-dry-run-real-app.md) | Dry-run: full chain on the real application | 100110, 100111 | ✅ | 2026-10-22 |     | 2026-10-20 |     | 2026-10-20 |

Tests can be replayed with this script -> run.sh.

- Once, to make it executable: `chmod +x detection/tests/run.sh`.
- Tests T-004 and T-005 can be replayed automatically (from the repo root, with Wazuh running):

```bash
chmod +x detection/tests/run.sh      # une seule fois
./detection/tests/run.sh             # tous les tests (~3 min 30)
./detection/tests/run.sh t004        # seulement T-004 (~20 s)
./detection/tests/run.sh t005        # seulement T-005 (~2 min)
```
