# Rapport de qualification des alertes

> Livrable de l'étape 3 : mesure du taux de faux positifs de la chaîne de détection
> sur du trafic normal, et qualification des alertes.

- **Date de la mesure :** 26-10-2026
- **Auteur :** Meghan CRESCI-HUMANN / Wyliam BURGER
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

Périmètre du ratio : les alertes des **règles custom du projet** (plage `100100`-`100199`,
contrat §8), seules alertes que la chaîne de détection SupportDesk produit. Les alertes **natives**
de Wazuh (évaluation de configuration SCA du manager, logs d'entraînement SSH de T-012, démons
Wazuh) ne portent pas sur l'application : elles sont comptées à part et exclues du ratio.

Sur une fenêtre de trafic **uniquement normal**, toute alerte custom est un faux positif : le ratio
vaut donc soit 100 %, soit `0 / 0` (non défini) si la chaîne reste muette. Le résultat est donc
exprimé de deux façons complémentaires :

- **fenêtre normale** : nombre de faux positifs rapporté au volume de trafic
  (`faux positifs / 1000 requêtes normales`, contrat §10 : « le volume et la période sont
  consignés avec le résultat ») ;
- **session complète** (fenêtre normale + scène d'attaque sur la même stack) : `faux positifs /
  total des alertes custom`, chaque alerte étant classée vrai ou faux positif.

Conditions de validité (contrat §10) : le script de trafic est **figé et reproductible** avant
le lancement de la mesure (`feat/W02-traffic-script`, version du 2026-10-22). Il est versionné
dans le dépôt (`supportdesk/scripts/traffic.js`) et produit un rapport JSON du trafic généré.

Fenêtre de mesure : depuis W13, la borne de fin `T1` est relevée **après** le délai de flush de
l'indexeur (`FLUSH_SECONDS`, 10 s par défaut), et non plus juste après le trafic. Les horodatages
d'alerte Wazuh sont des temps d'analyse (manager) plus le délai d'ingestion : fermer la fenêtre
avant le flush excluait silencieusement les alertes de la fin du trafic et pouvait sous-estimer
les faux positifs recherchés.

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

**0 faux positif pour 1062 requêtes normales (0 / 1000 requêtes).** Le ratio
`faux positifs / alertes custom` vaut `0 / 0` sur cette fenêtre (non défini, cf. §1) : aucune
alerte custom n'a été produite, il n'y a rien à classer.

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
  faux positifs de détection** (aucune règle custom ne cible les 5xx). Cause identifiée (rejouée
  le 2026-10-31) : toutes viennent de `POST /tickets/search` avec le terme légitime
  `probleme d'impression` du vocabulaire du script. La recherche concatène la saisie dans la
  requête SQL (`LIKE '%...%'`, la vulnérabilité d'AP-03) : l'apostrophe ferme la chaîne SQL et
  SQLite échoue (`near "impression": syntax error`, événement `internal_error` dans les logs).
  C'est donc le **symptôme fonctionnel de l'injection SQL volontaire** (D-005), pas un bug de
  charge : il n'est pas corrigé (l'application doit rester vulnérable) et le terme est conservé
  dans le script, car il prouve qu'une apostrophe isolée ne déclenche pas `100121` (cas
  « apostrophe » de T-009). Attendu : environ 1 recherche sur 9 (1 terme sur 9 du vocabulaire).
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
produit **0 faux positif** (0 pour 1000 requêtes normales ; ratio par alerte non défini sur une
fenêtre sans alerte, cf. §1). Les seuils des règles de corrélation (brute force,
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
| Alertes custom 100100-100199 | **0** (voir la limite ci-dessous)                                                    |
| Alertes natives              | 144, hors périmètre du ratio (§1)                                                     |
| **Faux positifs**            | **0 pour 1058 requêtes normales** (0 / 1000 requêtes) ; ratio fenêtre `0 / 0`         |
| **Session complète (§10)**   | **0 faux positif / 11 alertes custom = 0 %** (11 vrais positifs de la scène RB-04)   |

Rapport versionné : [`fp-report-20261030T121715.json`](../../detection/tests/fp-report-20261030T121715.json)
(sortie brute de l'outil, conservée telle quelle : son champ `interpretation` reprend l'ancien calcul
`0/144`, remplacé par la lecture ci-dessus ; le rapport de trafic brut généré à l'exécution,
`traffic-report-fp-*.json`, n'est pas versionné : convention `.gitignore` du repo, `traffic-report-*`). Script :
[`detection/tests/fp-measure.sh`](../../detection/tests/fp-measure.sh) (exit 2 si la fenêtre tourne à vide ou
remonte du 4xx : un verdict OK sur une fenêtre vide serait lui-même un faux positif de l'outil).

Les 11 réponses 500 confirment l'observation §6 (apostrophe légitime dans la recherche vulnérable,
aucune règle custom ne cible les 5xx).

**Alertes natives (144).** Elles n'ont pas été ventilées lors de cette exécution. Sur l'historique
de la stack locale de développement (16 au 31/10, 462 alertes natives), elles proviennent toutes de
`training.log` (T-012, règles SSH 5710/5712), du module SCA du manager, de `wazuh-monitord` et de
`logcollector` : **aucune ne provient de `app.jsonl`**. Depuis le 2026-10-31, `fp-measure.sh` produit
cette ventilation dans le rapport (`native_alerts_in_window`, par `rule.id` et `location`, avec le
compteur `from_app_jsonl`).

**Limite (levée le 2026-10-31, voir §11) : le 0 de cette mesure devait être reconfirmé.** La version de `fp-measure.sh` utilisée le
2026-10-30 comparait `rule.id` à un entier, alors que l'indexer renvoie une chaîne (`"100121"`) :
elle ignorait **toutes** les alertes custom et ne pouvait donc rendre que 0 (rejoué le 2026-10-31
sur une fenêtre locale contenant 153 alertes custom : ancienne logique 0, logique corrigée 153). Le
script est corrigé et la mesure de 600 s a été relancée (§11) : le 0 est confirmé. La requête `now-10m` de la §10, lancée juste après la fenêtre du 30/10 et qui en
recouvre la fin, allait déjà dans ce sens (seules les 11 alertes de la scène).

Confirmations de détection effective le même jour : T-004 PASS 3/3 avec les samples, et scène démo
RB-04 exécutée en direct (§10).

---

## 10. Démo live RB-04 (2026-10-30, même stack)

Scène exécutée après la fenêtre de mesure (12:27:xx UTC) via le runbook
[`RB-04-demo.md`](../../detection/runbooks/RB-04-demo.md) :

| Étape                                                     | Exécution                                   | Résultat Wazuh (indexer, `now-10m`)                                                 |
| --------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------- |
| Brute force (10 logins échoués `admin@supportdesk.local`) | curl ×10, 302 (verdict dans l'event, D-004) | `100110` ×9 (level 3, échec unitaire) + **`100111` level 10 (brute force agrégée)** |
| SQLi (`POST /tickets/search`, payload `' OR '1'='1`)      | login user + POST, 200                      | **`100121` level 10**                                                               |
| Dwell time                                                | requête → alerte indexée                    | **< 2 s** (ingestion + indexation)                                                  |

11 alertes custom au total, exactement celles attendues par la scène, aucune autre : la chaîne
détecte les deux attaques du démo sans bruit parasite. Le dashboard Grafana est resté alimenté
pendant toute la mesure (scrape `supportdesk` up).

---

## 11. Re-mesure avec l'outil corrigé (2026-10-31)

Re-mesure demandée par la limite de la §9. Même méthode (§1), même script de trafic (inchangé
depuis son dernier commit), `fp-measure.sh` corrigé : lecture des `rule.id` (chaînes), ventilation
des alertes natives, et appel de `traffic.js` en mode node local (l'ancien appel `node --base …`
omettait le chemin du script et ne fonctionnait qu'en mode conteneur, celui du LXC du 30/10).

| Élément                               | Valeur                                                                                                   |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Date                                  | 2026-10-31                                                                                               |
| Hôte                                  | poste de développement (8 c / 15 Go), stack consolidée reconstruite (`docker compose up -d --build`) : 6 services `Up (healthy)`, `wazuh.dashboard-init` terminé (exit 0) |
| Fenêtre                               | 600 s (13:45:50 → 13:55:53 UTC)                                                                          |
| Trafic normal                         | **1043 requêtes**, 6 sessions, **0 login échoué**                                                         |
| Statuts                               | 200 ×891, 302 ×140, 500 ×12 (les 12 : recherche `probleme d'impression`, cf. §6)                         |
| Ingestion Wazuh                       | logcollector : 1325 événements lus dans `app.jsonl` depuis le démarrage (dont les 1255 de la fenêtre) ; analysisd : **0 événement perdu** |
| Alertes custom 100100-100199          | **0**                                                                                                    |
| Alertes natives                       | 0 (`from_app_jsonl` : 0)                                                                                 |
| **Faux positifs**                     | **0 pour 1043 requêtes normales (0 / 1000 requêtes)**                                                    |
| Contrôle positif (juste après)        | SQLi `POST /tickets/search` depuis `198.51.100.200` → **`100121` level 10**, indexée **1,5 s** après la requête |

Rapport versionné : [`fp-report-20261031T134550.json`](../../detection/tests/fp-report-20261031T134550.json).

**Lecture.** Le 0 est cette fois établi par un outil capable de compter les alertes custom (vérifié
sur 153 alertes, §9), sur une fenêtre où la chaîne était effectivement active : tous les événements
de l'application ont été lus et analysés sans perte, et une attaque envoyée juste après la fenêtre
est détectée en 1,5 s. Le résultat de la §9 est **confirmé : 0 faux positif sur le trafic normal**.
