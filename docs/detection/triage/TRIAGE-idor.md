# Playbook de triage - IDOR sur l'export de tickets

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                                         | MITRE |
| ------ | ------ | --------------------------------------------------------------------- | ----- |
| 100150 | 8      | Export d'un ticket non possédé par un utilisateur non admin           | —     |
| 100151 | 10     | 5 exports de tickets distincts / 300 s par le même `user.id`          | —     |

Fichier : `detection/rules/100150_idor.xml`.

## 2. Ce que l'alerte signifie

L'endpoint `GET /tickets/:id/export` ne vérifie pas la propriété du ticket. Un utilisateur
authentifié peut changer l'identifiant dans l'URL et exporter le ticket d'un autre utilisateur.
La règle 100150 compare `user.id` et `target.owner_id` via `target.owned_by_user` ; la règle
100151 détecte l'énumération quand un même utilisateur exporte plusieurs tickets distincts qui
ne lui appartiennent pas. Les administrateurs sont exclus par la négation `user.role`.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100150` puis `rule.id:100151`.
2. **Champs à lire** : `user.id`, `user.name`, `user.role`, `target.id`, `target.owner_id`,
   `target.owned_by_user`, `event.action=export`, `source.ip`.
3. **Journal applicatif** : `detection/logs/app.jsonl`, événement `event.action=export` ;
   vérifier que `target.owned_by_user` vaut bien `"false"`.
4. **Grafana** : panneau des exports / statuts ; une série d'exports réussis (200) sans erreur
   est typique de l'IDOR, car l'application ne bloque rien.
5. **Vrai positif** : plusieurs exports de tickets distincts appartenant à d'autres utilisateurs
   (100151), ou un export isolé explicite sur un ticket sensible.
6. **Faux positif** : un utilisateur qui exporte une seule fois un ticket par erreur (mauvais
   identifiant), ou un ticket partagé dont le modèle de propriété est incomplet. Les exports
   légitimes du trafic normal ne visent que des tickets possédés (cf.
   [rapport de qualification](../alert-qualification-report.md)).

## 4. Action selon verdict

**Vrai positif**

- Suspendre ou surveiller le compte concerné et alerter le propriétaire des tickets exposés.
- Auditer l'historique des exports de l'utilisateur (`target.id`, horodatage) pour mesurer la
  fuite.
- Révoquer la session et, si nécessaire, réinitialiser les identifiants.
- Notifier les propriétaires des tickets concernés selon la procédure de confidentialité.

**Faux positif**

- Documenter l'identifiant mal saisi ou le partage légitime du ticket.
- Consigner la qualification dans le [rapport de qualification](../alert-qualification-report.md).
- Si un partage d'équipe est légitime, proposer une évolution du modèle de propriété, pas un
  élargissement silencieux de la règle.

## 5. Lien

- Runbook : pas de runbook dédié ; scénario couvert par le test T-008.
- Test : [T-008 - règles 100150/100151](../tests/T-008-rule-100150-idor.md)
- Contexte : [dashboard de détection](../dashboard.md)
