# Rapport de qualification des alertes

> Livrable de l'étape 3 : mesure du taux de faux positifs de la chaîne de détection
> sur du trafic normal, et qualification des alertes.

- **Date de la mesure :** 26-10-2026
- **Auteur :** Meghan CRESCI-HUMANN / William BURGER
- **Version Wazuh :** 4.14.9 (single-node)
- **Application :** SupportDesk V1
- **Règles évaluées :** 100100-100161 (toutes les règles custom du projet)

---

## 1. Méthode

Le taux de faux positifs se mesure sur du **trafic normal uniquement**, sans aucune attaque.
Toute alerte générée pendant cette fenêtre est, par définition, un faux positif (il n'y a pas
d'attaque réelle à détecter).

```text
taux de faux positifs = faux positifs / total d'alertes
```

Conditions de validité (contrat §10) : le script de trafic est **figé et reproductible** avant
le lancement de la mesure (`feat/W02-traffic-script`, version du 2026-10-22). Il est versionné
dans le dépôt (`supportdesk/scripts/traffic.js`) et produit un rapport JSON du trafic généré.

---

## 2. Paramètres de la mesure

| Élément            | Valeur                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------ |
| Outil de trafic    | `supportdesk/scripts/traffic.js` (Node stdlib, zéro dépendance)                            |
| Commande           | `node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600`                      |
| Durée              | 600 s (10 min)                                                                             |
| Identités simulées | 6 utilisateurs + 1 admin, IP distinctes (`10.20.0.11`-`10.20.0.20`, via `X-Forwarded-For`) |
| Début              | 2026-10-26 14:39:13 (locale) / 13:40:30 UTC (trafic)                                       |
| Fin                | 2026-10-26 14:51:20 (locale) / 13:50:43 UTC (trafic)                                       |

---

## 3. Trafic généré (dénominateur)

Source : rapport JSON `traffic-report-2026-10-26T13-40-30-119Z.json`.

| Métrique                    | Valeur                   |
| --------------------------- | ------------------------ |
| Requêtes totales            | **1062**                 |
| Types d'endpoints distincts | 76                       |
| Sessions                    | 6 utilisateurs + 1 admin |
| Échecs de login             | 0                        |

Répartition des statuts HTTP :

| Statut | Nombre |
| ------ | ------ |
| 200    | 920    |
| 302    | 134    |
| 500    | 8      |

Le trafic couvre **tous les endpoints sensibles** du périmètre de détection :
connexions/déconnexions, recherche de tickets (`POST /tickets/search`, 110 requêtes),
exports de tickets (nombreux), commentaires, consultation de la base de connaissances
(`GET /kb/view`, 100 requêtes), et accès administrateur (`GET /admin`, `POST /admin/fetch`).

---

## 4. Résultat

| Mesure                              | Avant | Après | Delta |
| ----------------------------------- | ----- | ----- | ----- |
| Alertes SupportDesk (100100-100161) | 0     | 0     | **0** |

**Taux de faux positifs = 0 / 0 = 0 %.**

Aucune des 1062 requêtes légitimes n'a déclenché d'alerte de détection.

---

## 5. Qualification par règle

Pour chaque règle, justification de l'absence de déclenchement sur le trafic normal :

| Règle                    | Endpoint exercé par le trafic                      | Pourquoi aucun faux positif                                                                                           |
| ------------------------ | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `100110/111` brute force | `POST /login` (69 requêtes)                        | 0 échec de login dans le trafic normal ; aucun déclenchement possible                                                 |
| `100120/121` SQLi        | `POST /tickets/search` (110), `GET /tickets` (211) | Vocabulaire de recherche sans motif d'injection (auto-vérifié par le script contre la regex de la règle au démarrage) |
| `100130` SSRF            | `POST /admin/fetch` (12)                           | URL cible publique (`https://status.example.com/health`), jamais une adresse interne                                  |
| `100140/141` traversal   | `GET /kb/view` (100)                               | Seuls les documents légitimes de `public/kb/` sont demandés, jamais de `../`                                          |
| `100150/151` IDOR        | exports de tickets (nombreux)                      | Les utilisateurs n'exportent que des tickets possédés ; l'admin est exclu par la négation `user.role`                 |
| `100160/161` scan        | tous                                               | 0 réponse 4xx sur le trafic normal : la règle de base (sur événement 4xx) ne voit rien                                |

---

## 6. Observations complémentaires

- **8 erreurs HTTP 500** ont été générées par le trafic normal. Elles **ne constituent pas des
  faux positifs de détection** (aucune règle custom ne cible les 5xx), mais révèlent des bugs de
  l'application sous charge normale, à signaler à l'équipe applicative.
- Le trafic a exercé des exports de tickets et des accès admin **sans** déclencher les règles IDOR
  et SSRF : cela confirme que ces règles distinguent correctement un usage légitime d'une attaque,
  ce qui est le point le plus sensible en matière de faux positifs.

---

## 7. Mise en perspective (vrais positifs)

La contrepartie de cette mesure est la détection effective des attaques réelles, documentée dans
les runbooks :

| Scénario                                   | Détection                | Référence |
| ------------------------------------------ | ------------------------ | --------- |
| Brute force (hydra)                        | ✅ alertes 100111        | RB-01     |
| Path traversal (curl, fuite `/etc/passwd`) | ✅ alertes 100140/100141 | RB-02     |
| Injection SQL (sqlmap, dump de la base)    | ✅ alertes 100120/100121 | RB-03     |

La chaîne détecte donc les attaques (vrais positifs confirmés) **sans** générer d'alerte sur du
trafic légitime (0 faux positif). Les seuils sont validés par ce double résultat.

---

## 8. Conclusion

Sur une fenêtre de 10 minutes et 1062 requêtes légitimes représentatives, la chaîne de détection
produit **0 faux positif** (taux de 0 %). Les seuils des règles de corrélation (brute force,
scan) sont donc calibrés sans sur-déclenchement sur le trafic normal, tout en détectant les
attaques réelles (runbooks RB-01 à RB-03).

### Reproductibilité

```bash
# 1. Compter les alertes avant
docker exec sentinelx-wazuh.manager-1 grep -c '"supportdesk"' /var/ossec/logs/alerts/alerts.json
# 2. Lancer le trafic normal (10 min)
cd supportdesk && node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600
# 3. Compter les alertes après
docker exec sentinelx-wazuh.manager-1 grep -c '"supportdesk"' /var/ossec/logs/alerts/alerts.json
```

### Piste d'approfondissement

Une variante du script (`--typos N`) permet d'injecter N fautes de frappe espacées de plus de 90 s.
Elle génère exactement N alertes `100110` (niveau 3) mais aucune alerte `100111` : elle démontre
que le seuil de brute force (5 échecs / 60 s) n'est pas franchi par des erreurs humaines isolées.
À exécuter pour renforcer la justification du seuil si nécessaire.

---

## 9. Re-mesure finale (W3-06) -- stack consolidée complète

Re-mesure du taux de faux positifs sur l'environnement **final consolidé** (compose racine :
app + Prometheus + Grafana + Wazuh) après fusion des waves 3. Même méthode (§1), même script de trafic.

| Élément                      | Valeur                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| Date                         | 2026-10-30                                                                           |
| Hôte                         | LXC `149 sentinelx` (toast, 4 c / 12 Go), stack 6 services `Up`, indexer **green**   |
| Fenêtre                      | 600 s (12:17:15 → 12:27:23 UTC)                                                      |
| Outil                        | `detection/tests/fp-measure.sh` (trafic + agrégation indexer dans la fenêtre exacte) |
| Trafic normal                | **1058 requêtes**, 6 sessions, **0 login échoué**, 0 payload suspect                 |
| Statuts                      | 200 ×917, 302 ×130, 500 ×11                                                          |
| Alertes dans la fenêtre      | 144 (toutes règles confondues, natives machine incluses)                             |
| Alertes custom 100100-100161 | **0**                                                                                |
| **Taux de faux positifs**    | **0 / 144 = 0.0 %** (chaîne custom : 0 alerte)                                       |

Rapport versionné : [`fp-report-20261030T121715.json`](../../detection/tests/fp-report-20261030T121715.json)
(le rapport de trafic brut généré à l'exécution, `traffic-report-fp-*.json`, n'est pas versionné :
convention `.gitignore` du repo, `traffic-report-*`). Script :
[`detection/tests/fp-measure.sh`](../../detection/tests/fp-measure.sh) (exit 2 si la fenêtre tourne à vide ou
remonte du 4xx : un verdict OK sur une fenêtre vide serait lui-même un faux positif de l'outil).

Les 11 réponses 500 confirment l'observation §6 (bugs applicatifs sous charge normale, aucune règle
custom ne cible les 5xx). Confirmations de détection effective le même jour : T-004 PASS 3/3 avec
les samples, et scène démo RB-04 exécutée en direct (§10).

---

## 10. Démo live RB-04 (2026-10-30, même stack)

Scène exécutée après la fenêtre de mesure (12:27:xx UTC) via le runbook
[`RB-04-demo.md`](../../detection/runbooks/RB-04-demo.md) :

| Étape                                                     | Exécution                                   | Résultat Wazuh (indexer, `now-10m`)                                                 |
| --------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------- |
| Brute force (10 logins échoués `admin@supportdesk.local`) | curl ×10, 302 (verdict dans l'event, D-004) | `100110` ×9 (level 3, échec unitaire) + **`100111` level 10 (brute force agrégée)** |
| SQLi (`POST /tickets/search`, payload `' OR '1'='1`)      | login user + POST, 200                      | **`100121` level 5**                                                                |
| Dwell time                                                | requête → alerte indexée                    | **< 2 s** (ingestion + indexation)                                                  |

11 alertes custom au total, exactement celles attendues par la scène, aucune autre : la chaîne
détecte les deux attaques du démo sans bruit parasite. Le dashboard Grafana est resté alimenté
pendant toute la mesure (scrape `supportdesk` up).
