# Playbook de triage - Brute force sur /login

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                     | MITRE       |
| ------ | ------ | ------------------------------------------------- | ----------- |
| 100110 | 3      | Échec de login unitaire (parente : 100100)        | —           |
| 100111 | 10     | 5 échecs / 60 s depuis la même `source.ip`        | T1110.001   |

Fichier : `detection/rules/100110_bruteforce.xml`.

## 2. Ce que l'alerte signifie

Un client enchaîne les tentatives de connexion échouées sur `POST /login`. La règle 100110
trace chaque essai ; la règle 100111 agrège les échecs provenant de la même IP et signale une
attaque par force brute ou par password guessing. L'attaque peut viser un compte connu
(`user.name`) ou tester un grand nombre d'adresses.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100111` (ou `rule.id:100110`), période autour de l'alerte.
2. **Journal applicatif** : `detection/logs/app.jsonl`, chercher `event.category=authentication`,
   `event.action=login`, `event.outcome=failure` sur la même `source.ip`.
3. **Champs à relever** : `source.ip`, `user.name`, `event.outcome`, `http.response.status_code`,
   `user_agent.original`. Compter les échecs et vérifier s'ils sont répartis sur plusieurs mots
   de passe ou plusieurs comptes.
4. **Grafana** : dashboard « SupportDesk — application overview », panneau *Auth attempts / s by
   outcome* ; un pic de la série `outcome="failure"` confirme la rafale.
5. **Vrai positif** : au moins 5 échecs en 60 s depuis la même IP, avec des identifiants ou des
   mots de passe variés. Un `event.outcome=success` après la rafale signale une compromission.
6. **Faux positif** : quelques fautes de frappe isolées d'un utilisateur légitime, espacées de
   plus de 90 s. Le mode `--typos 2` du script de trafic reproduit ce cas documenté dans le
   [rapport de qualification](../alert-qualification-report.md) : il produit des 100110, jamais
   de 100111.

## 4. Action selon verdict

**Vrai positif**

- Alerter l'astreinte sécurité et le propriétaire du compte ciblé.
- Vérifier immédiatement si un login a réussi après les échecs (`event.outcome=success`).
- Si succès : invalider les sessions du compte, réinitialiser le mot de passe, auditer les
  actions de la session (exports de tickets, modifications).
- Bloquer ou limiter l'IP source au niveau du reverse proxy ; conserver les preuves
  (`rule.id`, `source.ip`, fenêtre temporelle, `user.name`).

**Faux positif**

- Documenter le motif : utilisateur légitime, nombre d'essais, intervalle entre les essais.
- Consigner la qualification dans le [rapport de qualification](../alert-qualification-report.md)
  sans modifier la règle si le cas reste sous le seuil.
- Si le cas se répète, proposer un ajustement de `frequency`/`timeframe`, jamais un blocage
  large d'IP légitimes.

## 5. Lien

- Runbook : [RB-01 - Brute force](../../../detection/runbooks/RB-01-bruteforce.md)
- Tests : [T-002 - règle 100110](../tests/T-002-rule-100110-login-failure.md),
  [T-003 - règle 100111](../tests/T-003-rule-100111-bruteforce.md)
- Contexte : [dashboard de détection](../dashboard.md)
