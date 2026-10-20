# T-009 - Règles 100120 / 100121 : injection SQL

- **Date :** 20-10-2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node)
- **Contrat :** CONTRACT.md v0.3.0-draft (§4.1, §8)
- **Règles testées :** 100120 (query), 100121 (body)
- **Fichier de règles :** `detection/rules/100120_sql_injection.xml`
- **MITRE ATT&CK :** T1190 - Exploit Public-Facing Application
- **Statut :** ✅ Validé (4 cas sur 4) - limite d'évasion documentée

## Contexte

Deux endpoints concatènent directement l'entrée utilisateur dans une requête SQL (pas de requête préparée) :

- `GET /tickets` : les paramètres `status`, `priority`, `sort`, `dir` sont insérés dans le `WHERE` et l'`ORDER BY`. Le paramètre `sort` est injectable directement.
- `POST /tickets/search` : le champ `search` est inséré dans un `LIKE '%…%'`.

Ces entrées sont visibles dans `http.request.query` et `http.request.body` (contrat §4.1, validés en T-006).

## Règles testées

Deux règles au même niveau (10), séparées pour indiquer **où** le motif a été vu :

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

### Choix de conception

- **Motifs ciblés, pas caractères isolés** : la règle cherche des combinaisons typiques d'injection (`union select`, `or 1=1`, `' or '`, `; drop`, `sleep(`, `benchmark(`, `information_schema`, commentaires `-- ` et `/*`), et non une simple apostrophe. Une apostrophe seule est fréquente dans une recherche légitime : l'inclure provoquerait beaucoup de faux positifs.
- **Deux règles distinctes** pour localiser l'injection (URL ou corps) dans la description.
- **Insensible à la casse** (`(?i)`) et tolérant aux espaces (`\s*`).

## Cas testés (`wazuh-logtest`)

| Cas                       | Échantillon               | Entrée                                                | Attendu           | Obtenu          |
| ------------------------- | ------------------------- | ----------------------------------------------------- | ----------------- | --------------- |
| SQLi dans l'URL           | `sqli_query.jsonl`        | `sort=…) UNION SELECT username,password FROM users--` | 100120, niveau 10 | ✅              |
| SQLi dans le corps        | `sqli_body.jsonl`         | `search=xyz' OR '1'='1`                               | 100121, niveau 10 | ✅              |
| Recherche normale         | `search_normal.jsonl`     | `search=imprimante en panne`                          | aucune alerte     | ✅ 100100 seule |
| Recherche avec apostrophe | `search_apostrophe.jsonl` | `search=probleme d'impression`                        | aucune alerte     | ✅ 100100 seule |

Le dernier cas est le test de faux positif clé : une apostrophe isolée ne déclenche pas la règle, car le motif exige `'` suivi de `or`.

Enrichissement MITRE automatique : _Initial Access_, _Exploit Public-Facing Application_.

## Indexation

```bash
cat detection/samples/sqli_query.jsonl detection/samples/sqli_body.jsonl >> detection/logs/app.jsonl
sleep 20
docker logs --since 1m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:100120&size=1" \
  | python3 -m json.tool | grep '"query"'
```

Résultat : aucune erreur, et l'alerte indexée contient
`"query": "sort=created_at) UNION SELECT username,password FROM users--"`.

## Limite connue : contournement par encodage

La règle repère les mots-clés **en clair**. Le contrat ne décode l'entrée qu'une seule fois (§4.1). Un payload encodé une fois de plus (par exemple `%55NION` pour `UNION`, ou une injection entièrement URL-encodée) n'est donc pas reconnu.

Ce n'est pas corrigé ici volontairement : c'est la base du **scénario d'évasion bonus** (« payload encoding »), où l'on montre le contournement puis on durcit la règle (décodage supplémentaire côté application, ou motifs tenant compte des formes encodées).

Autres limites :

- Détection par signatures : un motif d'injection non listé passe inaperçu.
- `status` et `priority` de `/tickets` sont aussi injectables mais plus contraints ; non spécifiquement ciblés.
- Testé sur échantillons conformes au contrat : à rejouer avec sqlmap sur l'application V1.

## Actions de suivi

- [ ] Rejouer avec sqlmap pendant l'attaque réelle (attack plan SQLi) et mesurer la couverture.
- [ ] Scénario d'évasion : payload encodé, documenter l'échec, durcir la règle.
- [ ] Mesurer les faux positifs sur le trafic normal (script de trafic).
