# T-002 - Règle 100110 : échec de login unitaire

- **Date :** 15/10/2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node, wazuh-docker)
- **Contrat :** CONTRACT.md v0.1.0-draft
- **Règles testées :** 100100 (parente), 100110
- **Fichier de règles :** `detection/rules/local_rules.xml`
- **Statut :** ✅ Validé

## Objectif

Vérifier que :

1. la règle parente `100100` reconnaît les logs SupportDesk (`service.name = supportdesk`) ;
2. la règle `100110` se déclenche sur chaque échec de login (`event.category = authentication`, `event.action = login`, `event.outcome = failure`) ;
3. l'alerte contient le contexte attendu (utilisateur et IP source) ;
4. la règle native `1002`, observée dans T-001, ne prend plus le dessus.

## Règle testée

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

## Procédure

1. Copier les règles dans le conteneur et redémarrer le manager :
   ```bash
   docker cp detection/rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
   docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
   docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml
   docker restart single-node-wazuh.manager-1
   ```
2. Vérifier l'absence d'erreur de chargement :
   ```bash
   docker exec single-node-wazuh.manager-1 tail -n 50 /var/ossec/logs/ossec.log | grep -iE "error|critical|warning"
   ```
   Résultat : aucune ligne.
3. Lancer `wazuh-logtest` et coller une fois la ligne de `detection/samples/login_failure.json` :
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```

## Résultat attendu / obtenu

| Critère           | Attendu                                | Obtenu                                                     |
| ----------------- | -------------------------------------- | ---------------------------------------------------------- |
| Décodeur          | `json`                                 | `json` ✅                                                  |
| Règle déclenchée  | `100110`                               | `100110` ✅                                                |
| Niveau            | 3                                      | 3 ✅                                                       |
| Description       | utilisateur + IP source                | `SupportDesk: failed login for admin from 203.0.113.42` ✅ |
| Groupes           | `supportdesk`, `authentication_failed` | `supportdesk`, `authentication_failed` ✅                  |
| Alerte générée    | oui (niveau ≥ 3)                       | `Alert to be generated` ✅                                 |
| Règle native 1002 | ne matche plus                         | ne matche plus ✅                                          |

## Conclusion

La règle parente `100100` capte bien les logs SupportDesk et prend le pas sur la règle native générique `1002` (observée dans T-001). La règle `100110` produit une alerte de niveau 3 à chaque échec de login, avec le contexte nécessaire au triage (utilisateur ciblé et IP source).

**Point d'attention :** ce test utilise une ligne d'exemple conforme au contrat. Il devra être rejoué avec un log réellement émis par l'application V1 (dry-run, étape 2).

<details>
<summary>Sortie wazuh-logtest (1ʳᵉ ligne)</summary>

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
