# T-007 - Règles 100140 / 100141 : path traversal sur /kb/view

- **Date :** 20-10-2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node)
- **Contrat :** CONTRACT.md v0.3.0-draft (§4.1, §8)
- **Règles testées :** 100140, 100141
- **Fichier de règles :** `detection/rules/100140_path_traversal.xml`
- **MITRE ATT&CK :** T1190 - Exploit Public-Facing Application
- **Statut :** ✅ Validé (3 cas sur 3)

## Contexte

`GET /kb/view?doc=…` construit le chemin du fichier à lire avec le paramètre `doc`, sans vérifier qu'il reste dans le dossier `public/kb`. Une séquence `../` permet donc de lire des fichiers en dehors de la base de connaissances.

La requête est visible dans les logs grâce au champ `http.request.query` (contrat §4.1) ; le document demandé est aussi repris dans `target.id`.

## Règles testées

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

### Choix de conception

- **Deux niveaux de sévérité** : une tentative (niveau 7) n'a pas la même gravité qu'une lecture réussie (niveau 12). Le statut HTTP 200 indique que l'application a renvoyé un contenu, donc que le fichier a probablement été lu.
- **Motif recherché** : `../`, `..\` (variante Windows) et `%2e%2e` (points encodés, visibles si la requête était doublement encodée, puisque le contrat impose un seul décodage).
- **`type="pcre2"`** : expressions régulières standard, plus lisibles que le moteur par défaut de Wazuh.
- **Restriction à `/kb/view`** : limite les faux positifs sur d'autres endpoints.

## Procédure

```bash
docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# coller successivement les trois échantillons
```

Puis vérification de bout en bout (indexation) :

```bash
cat detection/samples/kb_view.jsonl detection/samples/kb_view_traversal_success.jsonl >> detection/logs/app.jsonl
sleep 20
docker logs --since 1m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:100141&size=1" \
  | python3 -m json.tool | grep '"query"'
```

## Résultats

| Cas                  | Échantillon                       | Requête                  | Statut | Attendu           | Obtenu                    |
| -------------------- | --------------------------------- | ------------------------ | ------ | ----------------- | ------------------------- |
| Tentative échouée    | `kb_view.jsonl`                   | `doc=../../etc/hostname` | 404    | 100140, niveau 7  | ✅ 100140, niveau 7       |
| Tentative réussie    | `kb_view_traversal_success.jsonl` | `doc=../../etc/hostname` | 200    | 100141, niveau 12 | ✅ 100141, niveau 12      |
| Consultation normale | `kb_view_normal.jsonl`            | `doc=vpn-guide.html`     | 200    | aucune alerte     | ✅ 100100 seule, niveau 0 |

Détails des alertes :

- Description : `SupportDesk: path traversal attempt on /kb/view from 203.0.113.42 (../../etc/hostname)` - l'IP et le fichier visé sont lisibles immédiatement.
- Enrichissement MITRE automatique : _Initial Access_, _Exploit Public-Facing Application_.
- 100141 porte `mail: 'True'` : Wazuh marque par défaut les alertes de niveau ≥ 12 pour notification immédiate (aucun serveur mail n'est configuré dans le lab).

Indexation : aucune erreur, et l'alerte 100141 contient `"query": "doc=../../etc/hostname"` dans l'indexer. **Le champ `http.request.query` est validé de bout en bout** (suivi de T-006).

<details>
<summary>Phase 3 - tentative échouée</summary>

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
<summary>Phase 3 - tentative réussie</summary>

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
<summary>Phase 3 - consultation normale</summary>

```
id: '100100'
level: '0'
description: 'SupportDesk: application event'
groups: '['supportdesk']'
mail: 'False'
```

</details>

## Limites connues

- **Contournement par chemin absolu** : un paramètre `doc` commençant directement par `/` ne contient pas `../`. Selon la façon dont l'application assemble le chemin, ce cas peut ou non permettre une lecture : à vérifier pendant l'attaque réelle.
- **Encodages plus poussés** (double encodage complet, variantes Unicode) : seule la forme `%2e%2e` est couverte.
- **Statut 200 ≠ certitude** : 100141 indique que l'application a répondu avec succès, pas la nature du fichier lu.
- Tests réalisés sur des échantillons conformes au contrat : à rejouer avec les logs réels de l'application V1.

## Actions de suivi

- [ ] Rejouer pendant l'attaque réelle (attack plan path traversal) et vérifier les cas limites ci-dessus.
- [ ] Ajouter les cas T-007 à `detection/tests/run.sh`.
