# Tests de détection

## T-001 - Compatibilité du schéma de log avec le décodeur JSON natif

- **Date :** 15/10/2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node, wazuh-docker)
- **Contrat :** CONTRACT.md v0.1.0-draft

**Objectif :** vérifier que le format JSON imbriqué (style ECS) du contrat est décodé par le décodeur `json` natif, sans décodeur custom.

**Commande :**

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

**Entrée :** ligne `auth failure` du contrat (voir `detection/samples/login_failure.json`).

**Résultat :**

- Décodeur utilisé : `json` ✅
- Tous les champs imbriqués sont extraits en notation pointée
  (`event.action`, `event.outcome`, `source.ip`, `user.name`, …) ✅
- Les nombres sont convertis en chaînes (`status_code: '302'`, `duration_ms: '38.200000'`)
- Règle déclenchée : `1002` (native, niveau 2, « Unknown problem somewhere in the system »),
  déclenchée par un mot-clé générique du log. Niveau < 3 : pas d'alerte au dashboard.

**Conclusion :** schéma compatible. Les règles custom peuvent cibler les champs via
`<field name="event.outcome">`. Comportement de la règle 1002 à revérifier
une fois la règle parente 100100 en place.

<details><summary>Sortie complète</summary>

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
