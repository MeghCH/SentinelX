# Playbook de triage - Injection SQL

## 1. Règle(s)

| Règle  | Niveau | Emplacement du motif             | MITRE |
| ------ | ------ | -------------------------------- | ----- |
| 100120 | 10     | `http.request.query` (GET)       | T1190 |
| 100121 | 10     | `http.request.body` (POST)       | T1190 |

Fichier : `detection/rules/100120_sql_injection.xml`. Les deux règles partagent le même motif
(`union select`, `or 1=1`, `'; drop`, `sleep(`, `information_schema`, commentaires SQL, etc.).

## 2. Ce que l'alerte signifie

Un client envoie une chaîne ressemblant à une injection SQL dans les paramètres d'URL ou dans un
corps de formulaire. Les endpoints concernés sont `GET /tickets` (paramètres `status`, `priority`,
`sort`, `dir`) et `POST /tickets/search` (champ `search`), qui concatènent l'entrée utilisateur
dans la requête SQL. L'objectif typique est d'altérer le `WHERE`, d'extraire la base ou de
provoquer une erreur exploitable.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100121` et `rule.id:100120`, période de l'alerte.
2. **Champs à lire** : `http.request.query`, `http.request.body` (payload exact, décodé une
   fois), `http.request.path`, `source.ip`, `user.name`, `http.response.status_code`.
3. **Journal applicatif** : `detection/logs/app.jsonl`, rechercher l'événement correspondant
   (`event.action=search` ou `request`) et vérifier le payload et le statut.
4. **Grafana** : panneaux *Statuts HTTP* et *taux d'erreurs* ; un pic de 500 accompagne souvent
   une injection qui casse la requête SQL.
5. **Vrai positif** : présence d'une structure d'injection (`UNION SELECT`, `OR 1=1`,
   `information_schema`, `SLEEP(`). Une tentative manuelle ou un scan sqlmap produisent
   plusieurs alertes.
6. **Faux positif** : texte légitime contenant un mot isolé comme « select » ou « union » sans
   la structure attendue. Une apostrophe seule dans une recherche (`probleme d'impression`)
   provoque parfois un 500 applicatif mais **ne déclenche pas** 100121 : c'est un cas documenté
   dans le [rapport de qualification](../alert-qualification-report.md), pas une alerte.

## 4. Action selon verdict

**Vrai positif**

- Traiter comme une tentative d'exfiltration : isoler l'IP, alerter l'astreinte.
- Auditer la base : comptes, tickets et journaux d'accès ; vérifier si des données ont été lues.
- Faire tourner les secrets d'application et les mots de passe si un dump est suspecté (les mots
  de passe de la V1 sont stockés en clair, cf. RB-03).
- Relever l'heure exacte, les payloads et les comptes utilisés pour l'analyse forensique.

**Faux positif**

- Documenter le payload légitime et expliquer pourquoi le motif de la règle ne devrait pas le
  concerner.
- Ajouter le cas au [rapport de qualification](../alert-qualification-report.md) et, si besoin,
  proposer un durcissement du motif sans affaiblir la détection.

## 5. Lien

- Runbook : [RB-03 - Injection SQL](../../../detection/runbooks/RB-03-sql-injection.md)
- Test : [T-009 - règles 100120/100121](../tests/T-009-rule-100120-sql-injection.md)
- Contexte : [dashboard de détection](../dashboard.md)
