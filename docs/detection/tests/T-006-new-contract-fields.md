# T-006 - Nouveaux champs du contrat v0.3.0

- **Date :** 19-10-2026
- **Auteur :** Meghan CRESCI-HUMANN
- **Version Wazuh :** 4.14.9 (single-node)
- **Contrat :** CONTRACT.md v0.3.0-draft (§4.1, §4.3)
- **Règles concernées :** 100100 (parente), 100110
- **Statut :** ✅ Décodage validé pour les trois champs - indexation validée pour `http.request.body`, à confirmer pour les deux autres

## Contexte

La lecture du code de SupportDesk a montré que la plupart des attaques (injection SQL, SSRF, path traversal, XSS stockée) passent par les paramètres de requête et les champs de formulaire, et que la détection d'IDOR nécessite le propriétaire de la ressource. Le contrat v0.3.0 ajoute donc :

| Champ                | Usage prévu                                                           |
| -------------------- | --------------------------------------------------------------------- |
| `http.request.query` | path traversal (`/kb/view`), injection SQL (`/tickets`)               |
| `http.request.body`  | injection SQL (`/tickets/search`), SSRF (`/admin/fetch`), XSS stockée |
| `target.owner_id`    | IDOR (`/tickets/:id/export`)                                          |

Conformément au contrat (§9), ces champs doivent être validés dans Wazuh **avant** leur implémentation dans l'application, pour éviter un nouveau conflit d'indexation comme celui de `data.url` (T-004).

## Échantillons

| Fichier                                      | Champ testé                               | Règle déclenchée attendue    |
| -------------------------------------------- | ----------------------------------------- | ---------------------------- |
| `detection/samples/login_failure_body.jsonl` | `http.request.body` (mot de passe masqué) | 100110 (niveau 3)            |
| `detection/samples/kb_view.jsonl`            | `http.request.query`, `target.id`         | 100100 uniquement (niveau 0) |
| `detection/samples/ticket_export.jsonl`      | `target.owner_id`, `user.id`              | 100100 uniquement (niveau 0) |

## Procédure

```bash
for f in kb_view ticket_export login_failure_body; do
  cat detection/samples/$f.jsonl >> detection/logs/app.jsonl; sleep 3
done
sleep 15

# 1. Refus d'indexation ?
docker logs --since 3m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"

# 2. http.request.body indexé ?
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?q=data.http.request.body:*&size=1" \
  | python3 -m json.tool | grep -A2 '"body"'

# 3. Décodage des deux autres échantillons
docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# coller le contenu de kb_view.jsonl puis de ticket_export.jsonl
```

## Résultats

| Vérification                | Résultat                                                 |
| --------------------------- | -------------------------------------------------------- |
| Refus d'indexation          | aucun ✅                                                 |
| `http.request.body` indexé  | ✅ `"body": "email=admin@techco.local&password=***"`     |
| Masquage du mot de passe    | ✅ `password=***`                                        |
| `http.request.query` décodé | ✅ `'doc=../../etc/hostname'` (caractères `../` intacts) |
| `target.id` décodé          | ✅ `'../../etc/hostname'`                                |
| `target.owner_id` décodé    | ✅ `'5'`                                                 |
| `user.id` décodé            | ✅ `'3'`                                                 |

Extrait de la phase 2 (`kb_view`) :

```
http.request.path: '/kb/view'
http.request.query: 'doc=../../etc/hostname'
http.response.status_code: '404'
target.id: '../../etc/hostname'
target.type: 'document'
```

Extrait de la phase 2 (`ticket_export`) :

```
http.request.path: '/tickets/7/export'
target.id: '7'
target.owner_id: '5'
target.type: 'ticket'
user.id: '3'
```

Les deux échantillons ne déclenchent que la règle parente `100100` (niveau 0) : aucune alerte n'est générée, donc rien n'est envoyé à l'indexer. C'est attendu, les règles traversal et IDOR n'existant pas encore.

## Constat : comparaison de champs pour l'IDOR

En préparant la règle IDOR, il apparaît que la syntaxe des règles Wazuh permet de tester la valeur d'un champ (`<field>`) et de corréler plusieurs événements (`same_field`, `different_field`), mais **pas de comparer deux champs d'un même événement** (ici, `user.id` différent de `target.owner_id`).

**Décision (contrat D-013) :** l'application calcule elle-même le champ `target.owned_by_user` (`"true"` / `"false"`, en texte pour respecter la règle « un type par champ »). La règle n'a plus qu'à tester `target.owned_by_user = false`. L'échantillon `ticket_export.jsonl` a été mis à jour en conséquence.

Approche complémentaire envisagée : détection comportementale d'un même utilisateur exportant de nombreux tickets différents sur une courte période.

## Conclusion

Les trois nouveaux champs du contrat v0.3.0 sont décodés correctement par le décodeur JSON natif, et `http.request.body` traverse toute la chaîne jusqu'à l'indexer sans conflit. Le contrat peut être proposé à l'équipe pour implémentation.

## Actions de suivi

- [ ] Confirmer l'indexation de `http.request.query`, `target.owner_id` et `target.owned_by_user` dès que les règles traversal (100140-100149) et IDOR (100150-100159) existent.
- [ ] Rejouer T-006 avec les logs réellement produits par l'application V1.
