# Playbook de triage - Événements SupportDesk de base (règle 100100)

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                      | MITRE |
| ------ | ------ | -------------------------------------------------- | ----- |
| 100100 | 0      | Tout événement JSON dont `service.name = supportdesk` | —     |

Fichier : `detection/rules/100100_supportdesk_base.xml`. C'est la règle **parente** : elle ne
décrit pas une attaque. Les règles 100110 à 100161 s'appuient sur elle.

## 2. Ce que l'alerte signifie

La règle 100100 reconnaît un événement applicatif SupportDesk décodé depuis `app.jsonl`. Son
niveau 0 signifie qu'elle sert de contexte : elle est évaluée en premier, puis les règles filles
ajoutent la sémantique d'attaque. Une alerte 100100 seule indique donc un événement applicatif
qui n'a déclenché aucune règle spécialisée : login réussi, recherche normale, consultation de
la base de connaissances, requête HTTP quelconque, ou erreur interne.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100100` (ou le groupe `rule.groups:supportdesk`) sur la
   période concernée.
2. **Champs à lire** : `event.category`, `event.action`, `event.outcome`, `http.request.path`,
   `source.ip`, `user.name`, `http.response.status_code`.
3. **Journal applicatif** : `detection/logs/app.jsonl`, retrouver la ligne par `trace.id` et
   confirmer qu'elle ne correspond à aucune règle 1001xx spécialisée.
4. **Grafana** : dashboard « SupportDesk — application overview » (rate, p95, taux d'erreurs)
   pour distinguer un simple événement d'une anomalie de trafic.
5. **Vrai positif** : une alerte 100100 seule n'est généralement pas un incident. Elle devient
   pertinente si elle accompagne une action sensible inattendue (export massif, accès admin,
   changement de rôle) ou une séquence précédant une alerte d'attaque.
6. **Faux positif** : tout le trafic applicatif normal produit des 100100 de niveau 0 ; ce n'est
   pas un faux positif au sens du [rapport de qualification](../alert-qualification-report.md),
   car la règle parente n'est pas comptée comme détection d'attaque.

## 4. Action selon verdict

**Vrai positif / événement suspect**

- Corréler avec les règles filles (100110-100161) et les métriques Grafana sur la même fenêtre.
- Si l'événement précède une attaque, conserver la ligne `app.jsonl` et le `trace.id` comme
  preuve pour l'analyse forensique.
- Si l'action sensible n'est couverte par aucune règle, ouvrir un ticket d'amélioration de la
  détection plutôt que d'agir sur la seule alerte 100100.

**Faux positif**

- Aucune action : c'est le fonctionnement attendu de la règle parente.
- Ne pas désactiver 100100 : les règles filles cesseraient de fonctionner.

## 5. Lien

- Runbook : pas de runbook dédié ; la chaîne complète est décrite dans
  [RB-04 - démo](../../../detection/runbooks/RB-04-demo.md).
- Tests : [T-001 - décodage JSON](../tests/T-001-json-decoder-compat.md),
  [T-004 - chaîne de bout en bout](../tests/T-004-end-to-end-chain.md),
  [T-006 - champs du contrat](../tests/T-006-new-contract-fields.md)
- Contexte : [dashboard de détection](../dashboard.md)
