# T-002 - Rule 100110: single login failure

- **Date:** 15/10/2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node, wazuh-docker)
- **Contract:** CONTRACT.md v0.1.0-draft
- **Rules tested:** 100100 (parent), 100110
- **Rules file:** `detection/rules/local_rules.xml`
- **Status:** ✅ Validated

## Objective

Verify that:

1. parent rule `100100` recognizes SupportDesk logs (`service.name = supportdesk`);
2. rule `100110` triggers on every login failure (`event.category = authentication`, `event.action = login`, `event.outcome = failure`);
3. the alert contains the expected context (user and source IP);
4. native rule `1002`, observed in T-001, no longer takes precedence.

## Rule tested

```xml
<rule id="100110" level="3">
  <if_sid>100100</if_sid>
  <field name="event.category">^authentication$</field>
  <field name="event.action">^login$</field>
  <field name="event.outcome">^failure$</field>
  <description>SupportDesk: failed login for $(user.name) from $(source.ip)</description>
  <group>authentication_failed,</group>
</rule>
```

## Procedure

1. Copy the rules into the container and restart the manager:
   ```bash
   docker cp detection/rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
   docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
   docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml
   docker restart single-node-wazuh.manager-1
   ```
2. Check that no loading error appears:
   ```bash
   docker exec single-node-wazuh.manager-1 tail -n 50 /var/ossec/logs/ossec.log | grep -iE "error|critical|warning"
   ```
   Result: no lines.
3. Start `wazuh-logtest` and paste the line from `detection/samples/login_failure.jsonl` once:
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```

## Expected / obtained result

| Criterion | Expected | Obtained |
| ----------------- | -------------------------------------- | ---------------------------------------------------------- |
| Decoder | `json` | `json` ✅ |
| Triggered rule | `100110` | `100110` ✅ |
| Level | 3 | 3 ✅ |
| Description | user + source IP | `SupportDesk: failed login for admin from 203.0.113.42` ✅ |
| Groups | `supportdesk`, `authentication_failed` | `supportdesk`, `authentication_failed` ✅ |
| Alert generated | yes (level ≥ 3) | `Alert to be generated` ✅ |
| Native rule 1002 | no longer matches | no longer matches ✅ |

## Conclusion

Parent rule `100100` correctly captures SupportDesk logs and takes precedence over generic native rule `1002` (observed in T-001). Rule `100110` produces a level 3 alert on every login failure, with the context required for triage (targeted user and source IP).

**Caveat:** this test uses a contract-compliant sample line. It must be replayed with a log actually emitted by the V1 application (dry-run, step 2).

<details>
<summary>wazuh-logtest output (first line)</summary>

```
**Phase 2: Completed decoding.
        name: 'json'
        event.action: 'login'
        event.category: 'authentication'
        event.outcome: 'failure'
        service.name: 'supportdesk'
        source.ip: '203.0.113.42'
        user.name: 'admin'
        [...]

**Phase 3: Completed filtering (rules).
        id: '100110'
        level: '3'
        description: 'SupportDesk: failed login for admin from 203.0.113.42'
        groups: '['supportdesk', 'authentication_failed']'
        firedtimes: '1'
        mail: 'False'
**Alert to be generated.
```

</details>
