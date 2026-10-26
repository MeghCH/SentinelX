# Detection tests

## T-001 - Log schema compatibility with the native JSON decoder

- **Date:** 15/10/2026
- **Author:** Meghan CRESCI-HUMANN
- **Wazuh version:** 4.14.9 (single-node, wazuh-docker)
- **Contract:** CONTRACT.md v0.1.0-draft

**Objective:** verify that the contract's nested JSON format (ECS style) is decoded by the native `json` decoder, with no custom decoder.

**Command:**

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

**Input:** the contract's `auth failure` line (see `detection/samples/login_failure.json`).

**Result:**

- Decoder used: `json` ✅
- All nested fields are extracted in dot notation
  (`event.action`, `event.outcome`, `source.ip`, `user.name`, …) ✅
- Numbers are converted to strings (`status_code: '302'`, `duration_ms: '38.200000'`)
- Rule triggered: `1002` (native, level 2, "Unknown problem somewhere in the system"),
  triggered by a generic keyword in the log. Level < 3: no alert in the dashboard.

**Conclusion:** schema is compatible. Custom rules can target fields via
`<field name="event.outcome">`. Rule 1002's behavior must be re-checked
once parent rule 100100 is in place.

<details><summary>Full output</summary>

```
➜  single-node git:(v4.14.9) docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
Starting wazuh-logtest v4.14.9
Type one log per line

{"@timestamp":"2026-10-15T14:32:11.423Z","event":{"dataset":"supportdesk.application","kind":"event","category":"authentication","action":"login","outcome":"failure"},"log":{"level":"warn"},"message":"Invalid credentials","service":{"name":"supportdesk","version":"1.0.0"},"trace":{"id":"3b2a6c1e-8f4d-4a51-9c2b-1d7e5f0a9b3c"},"http":{"request":{"method":"POST"},"response":{"status_code":302,"duration_ms":38.2}},"url":{"path":"/login"},"source":{"ip":"203.0.113.42"},"user_agent":{"original":"curl/8.5.0"},"user":{"name":"admin"}}

**Phase 1: Completed pre-decoding.
	full event: '{"@timestamp":"2026-10-15T14:32:11.423Z","event":{"dataset":"supportdesk.application","kind":"event","category":"authentication","action":"login","outcome":"failure"},"log":{"level":"warn"},"message":"Invalid credentials","service":{"name":"supportdesk","version":"1.0.0"},"trace":{"id":"3b2a6c1e-8f4d-4a51-9c2b-1d7e5f0a9b3c"},"http":{"request":{"method":"POST"},"response":{"status_code":302,"duration_ms":38.2}},"url":{"path":"/login"},"source":{"ip":"203.0.113.42"},"user_agent":{"original":"curl/8.5.0"},"user":{"name":"admin"}}'

**Phase 2: Completed decoding.
	name: 'json'
	@timestamp: '2026-10-15T14:32:11.423Z'
	event.action: 'login'
	event.category: 'authentication'
	event.dataset: 'supportdesk.application'
	event.kind: 'event'
	event.outcome: 'failure'
	http.request.method: 'POST'
	http.response.duration_ms: '38.200000'
	http.response.status_code: '302'
	log.level: 'warn'
	message: 'Invalid credentials'
	service.name: 'supportdesk'
	service.version: '1.0.0'
	source.ip: '203.0.113.42'
	trace.id: '3b2a6c1e-8f4d-4a51-9c2b-1d7e5f0a9b3c'
	url.path: '/login'
	user.name: 'admin'
	user_agent.original: 'curl/8.5.0'

**Phase 3: Completed filtering (rules).
	id: '1002'
	level: '2'
	description: 'Unknown problem somewhere in the system.'
	groups: '['syslog', 'errors']'
	firedtimes: '1'
	gpg13: '['4.3']'
	mail: 'False'
```

</details>
