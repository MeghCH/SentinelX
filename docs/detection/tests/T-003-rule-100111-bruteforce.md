# T-003 - Règle 100111 : brute force sur /login

- **Date :** 15/10/2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node, wazuh-docker)
- **Contrat :** CONTRACT.md v0.1.0-draft
- **Règles testées :** 100110, 100111
- **Fichier de règles :** `detection/rules/local_rules.xml`
- **MITRE ATT&CK :** T1110.001 - Password Guessing
- **Statut :** ✅ Validé (seuil provisoire)

## Objectif

Vérifier que la règle de corrélation `100111` :

1. se déclenche après un nombre défini d'échecs de login depuis la même IP dans une fenêtre de temps ;
2. produit une alerte de niveau 10 avec le mapping MITRE ;
3. mesurer précisément à quel événement elle se déclenche et ce qui se passe ensuite.

## Règle testée

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

Seuil provisoire : **5 échecs en 60 secondes depuis la même `source.ip`**. Valeur volontairement basse pour le test ; elle sera ajustée et justifiée dans l'attack plan « Brute force » et validée avec le script de trafic réaliste (faux positifs).

## Procédure

1. Règles chargées comme dans T-002.
2. Lancer `wazuh-logtest` :
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
3. Coller **6 fois de suite**, dans la même session, la ligne de `detection/samples/login_failure.json` (même IP `203.0.113.42`).
4. Relever la règle déclenchée à chaque ligne.

## Résultat obtenu

| Ligne | Règle      | Niveau | `firedtimes` | Remarque                                  |
| ----- | ---------- | ------ | ------------ | ----------------------------------------- |
| 1     | 100110     | 3      | 1            | Échec unitaire                            |
| 2     | 100110     | 3      | 2            |                                           |
| 3     | 100110     | 3      | 3            |                                           |
| 4     | 100110     | 3      | 4            |                                           |
| 5     | **100111** | **10** | 1            | **Brute force détecté**                   |
| 6     | 100110     | 3      | 5            | Le compteur de corrélation repart de zéro |

Détails de l'alerte 100111 :

- Description : `SupportDesk: possible brute force on /login from 203.0.113.42` ✅
- Groupes : `supportdesk`, `authentication_failures` ✅
- `frequency: '5'` ✅
- Enrichissement MITRE automatique par Wazuh : `T1110.001`, tactique _Credential Access_, technique _Password Guessing_ ✅

## Analyse

- **Déclenchement :** avec `frequency="5"`, l'alerte se déclenche sur le **5ᵉ événement**, celui-ci inclus. Les 4 premiers produisent l'alerte unitaire 100110, le 5ᵉ est remplacé par l'alerte 100111.
- **Après déclenchement :** le 6ᵉ échec retombe sur 100110. La corrélation repart de zéro après chaque alerte 100111.
- **Conséquence opérationnelle :** pendant un brute force réel (outil type hydra, plusieurs centaines de tentatives), on obtiendrait **une alerte de niveau 10 tous les 5 échecs**, soit potentiellement des centaines d'alertes identiques pour une seule attaque. Risque de saturation du dashboard.

## Limites connues

- Test réalisé avec une seule IP source. Le comportement avec plusieurs IP en parallèle (la corrélation doit rester séparée par IP via `same_field`) reste à vérifier.
- Le `timeframe` n'a pas été testé explicitement (toutes les lignes ont été envoyées en moins de 60 s). Un test avec des échecs espacés de plus de 60 s doit confirmer l'absence d'alerte.
- La détection repose sur `source.ip`. Si l'application journalise l'IP du bridge Docker (cf. contrat), toutes les requêtes semblent venir de la même source et la règle génère des faux positifs. À valider lors du dry-run.
- Un attaquant qui reste sous le seuil (lenteur) ou fait tourner ses IP n'est pas détecté. Piste pour le scénario bonus d'évasion.

## Actions de suivi

- [ ] Rejouer 10 lignes pour confirmer qu'une 2ᵉ alerte 100111 apparaît à la 10ᵉ.
- [ ] Tester deux IP différentes en alternance (corrélation séparée attendue).
- [ ] Tester le dépassement du `timeframe`.
- [ ] Limiter la répétition de l'alerte (attribut `ignore` sur la règle) et documenter le choix.
- [ ] Fixer le seuil définitif dans l'attack plan et le valider avec le script de trafic réaliste.

<details>
<summary>Sortie wazuh-logtest (5ᵉ ligne)</summary>

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
