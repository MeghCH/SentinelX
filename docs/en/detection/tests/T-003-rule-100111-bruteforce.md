# T-003 - Rule 100111: brute force on /login

- **Date:** 15/10/2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node, wazuh-docker)
- **Contract:** CONTRACT.md v0.1.0-draft
- **Rules tested:** 100110, 100111
- **Rules file:** `detection/rules/local_rules.xml`
- **MITRE ATT&CK:** T1110.001 - Password Guessing
- **Status:** ✅ Validated (provisional threshold)

## Objective

Verify that correlation rule `100111`:

1. triggers after a defined number of login failures from the same IP within a time window;
2. produces a level 10 alert with the MITRE mapping;
3. measure precisely at which event it triggers and what happens next.

## Rule tested

```xml
<rule id="100111" level="10" frequency="5" timeframe="60">
  <if_matched_sid>100110</if_matched_sid>
  <same_field>source.ip</same_field>
  <description>SupportDesk: possible brute force on /login from $(source.ip)</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

Provisional threshold: **5 failures in 60 seconds from the same `source.ip`**. Value deliberately low for testing; it will be adjusted and justified in the "Brute force" attack plan and validated with the realistic-traffic script (false positives).

## Procedure

1. Rules loaded as in T-002.
2. Start `wazuh-logtest`:
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
3. Paste the line from `detection/samples/login_failure.jsonl` **6 times in a row**, in the same session (same IP `203.0.113.42`).
4. Record the rule triggered for each line.

## Result obtained

| Line | Rule | Level | `firedtimes` | Note |
| ----- | ---------- | ------ | ------------ | ----------------------------------------- |
| 1 | 100110 | 3 | 1 | Single failure |
| 2     | 100110     | 3      | 2            |                                           |
| 3     | 100110     | 3      | 3            |                                           |
| 4     | 100110     | 3      | 4            |                                           |
| 5 | **100111** | **10** | 1 | **Brute force detected** |
| 6 | 100110 | 3 | 5 | The correlation counter restarts from zero |

Details of alert 100111:

- Description: `SupportDesk: possible brute force on /login from 203.0.113.42` ✅
- Groups: `supportdesk`, `authentication_failures` ✅
- `frequency: '5'` ✅
- Automatic MITRE enrichment by Wazuh: `T1110.001`, tactic _Credential Access_, technique _Password Guessing_ ✅

## Analysis

- **Triggering:** with `frequency="5"`, the alert fires on the **5th event**, inclusive. The first 4 produce the single-failure 100110 alert; the 5th is replaced by the 100111 alert.
- **After triggering:** the 6th failure falls back to 100110. The correlation restarts from zero after each 100111 alert.
- **Operational consequence:** during a real brute force (a hydra-type tool, several hundred attempts), the rule would produce **one level 10 alert every 5 failures**, i.e. potentially hundreds of identical alerts for a single attack. Risk of dashboard saturation.

## Known limitations

- Test run with a single source IP. Behavior with several IPs in parallel (correlation should remain separated per IP via `same_field`) still needs to be verified.
- The `timeframe` was not tested explicitly (all lines were sent in under 60 s). A test with failures spaced more than 60 s apart must confirm that no alert is raised.
- Detection relies on `source.ip`. If the application logs the Docker bridge IP (see contract), all requests appear to come from the same source and the rule generates false positives. To be validated during the dry-run.
- An attacker who stays below the threshold (slow attempts) or rotates IPs is not detected. Candidate for the bonus evasion scenario.

## Follow-up actions

- [ ] Replay 10 lines to confirm that a 2nd 100111 alert appears at the 10th.
- [ ] Test two different IPs in alternation (separate correlation expected).
- [ ] Test exceeding the `timeframe`.
- [ ] Limit alert repetition (`ignore` attribute on the rule) and document the choice.
- [ ] Set the final threshold in the attack plan and validate it with the realistic-traffic script.

<details>
<summary>wazuh-logtest output (5th line)</summary>

```
**Phase 3: Completed filtering (rules).
        id: '100111'
        level: '10'
        description: 'SupportDesk: possible brute force on /login from 203.0.113.42'
        groups: '['supportdesk', 'authentication_failures']'
        firedtimes: '1'
        frequency: '5'
        mail: 'False'
        mitre.id: '['T1110.001']'
        mitre.tactic: '['Credential Access']'
        mitre.technique: '['Password Guessing']'
**Alert to be generated.
```

</details>
