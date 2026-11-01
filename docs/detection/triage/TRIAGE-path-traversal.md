# Playbook de triage - Path traversal sur /kb/view

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                              | MITRE |
| ------ | ------ | ---------------------------------------------------------- | ----- |
| 100140 | 7      | `/kb/view` avec `../`, `..\` ou `%2e%2e` dans la requête    | T1190 |
| 100141 | 12     | 100140 suivi d'une réponse HTTP 200 (lecture réussie)       | T1190 |

Fichier : `detection/rules/100140_path_traversal.xml`.

## 2. Ce que l'alerte signifie

Un client tente de sortir du dossier de la base de connaissances via le paramètre `doc` de
`GET /kb/view`. Les séquences `../`, leur variante `..\` ou leur encodage `%2e%2e` visent un
fichier hors de `public/kb` (`/etc/passwd`, code source, configuration). La règle 100140 signale
la tentative ; 100141 signale qu'elle a réussi, car le serveur a répondu 200 avec le contenu
demandé.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100140` puis `rule.id:100141` sur la même période.
2. **Champs à lire** : `http.request.query` (payload et profondeur des `../`), `http.request.path`,
   `target.id` (document demandé), `http.response.status_code`, `source.ip`, `user.name`.
3. **Journal applicatif** : `detection/logs/app.jsonl`, événement `event.action=kb_view` ;
   vérifier le statut et le payload exact.
4. **Grafana** : panneau *Statuts HTTP* ; une réponse 200 sur un payload de traversal est le
   signal d'une fuite confirmée.
5. **Vrai positif** : 100141 (niveau 12) est un incident confirmé : un fichier hors périmètre a
   été lu. 100140 seul est une tentative, à corréler avec d'autres essais de la même IP.
6. **Faux positif** : requêtes légitimes de documents présents dans `public/kb`, sans séquence
   de traversal, y compris les documents dont le nom contient un point. Le trafic normal
   n'utilise jamais `../` (cf. [rapport de qualification](../alert-qualification-report.md)).

## 4. Action selon verdict

**Vrai positif**

- Pour 100141 : traiter comme une divulgation de fichier confirmée. Isoler le conteneur,
  alerter l'astreinte et le propriétaire de l'application.
- Identifier les fichiers lus (payloads 200) et vérifier la présence de secrets ou de données
  personnelles ; faire tourner les secrets exposés.
- Auditer les sessions de l'utilisateur et les exports de tickets associés.
- Correctif applicatif : normaliser le chemin et vérifier qu'il reste dans le dossier KB.

**Faux positif**

- Documenter le document légitime et l'absence de traversal réelle.
- Consigner le cas dans le [rapport de qualification](../alert-qualification-report.md).

## 5. Lien

- Runbook : [RB-02 - Path traversal](../../../detection/runbooks/RB-02-path-traversal.md)
- Test : [T-007 - règles 100140/100141](../tests/T-007-rule-100140-path-traversal.md)
- Contexte : [dashboard de détection](../dashboard.md)
