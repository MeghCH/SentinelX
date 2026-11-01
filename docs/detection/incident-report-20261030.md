# Rapport d'incident -- Scène RB-04 du 2026-10-30

> Reconstruction de l'incident exécuté en direct lors de la démonstration RB-04 sur la
> stack consolidée (6 services). Livrable bonus du sujet : chronologie, IOCs et analyse
> structurée à partir des alertes réellement produites.

- **Date de l'incident :** 2026-10-30
- **Environnement :** LXC `sentinelx` (toast), stack consolidée 6 services `Up`, indexer green
- **Scénario de référence :** [RB-04 -- démo live](../../detection/runbooks/RB-04-demo.md), §8
- **Méthodologie d'attaque :** [RB-01 -- brute force](../../detection/runbooks/RB-01-bruteforce.md) et [RB-03 -- injection SQL](../../detection/runbooks/RB-03-sql-injection.md)
- **Sources de données :** journaux applicatifs JSONL (`detection/logs/app.jsonl`), alertes Wazuh custom du projet (`100100`-`100121`), rapports de faux positifs committés
- **Nature :** démonstration contrôlée de vulnérabilités volontaires (contexte scolaire)

## 1. Résumé exécutif

Le 2026-10-30, la scène RB-04 a enchaîné deux attaques contre SupportDesk : une
**force brute sur `/login`** (10 tentatives échouées pour `admin@supportdesk.local`) puis une
**injection SQL sur `/tickets/search`**, exécutée avec une session utilisateur légitime.

La chaîne a produit exactement les alertes attendues : **9 × 100110** (échec de login unitaire,
niveau 3), **1 × 100111** (corrélation brute force, niveau 10) et **1 × 100121** (injection SQL
dans le corps de requête, niveau 10), soit **11 alertes custom** au total.

L'impact applicatif est **nul** : les codes de réponse sont restés conformes (302 pour les échecs
de login, 200 pour la recherche injectée) et Grafana est resté alimenté. Le **dwell time observé
est inférieur à 2 secondes**. La mesure de faux positifs sur trafic normal donne **0 alerte
custom**, avant comme après l'incident (0 pour 1058 puis 0 pour 1043 requêtes normales).

## 2. Chronologie (timeline)

Les horodatages absolus ne sont pas consignés dans la §8 de RB-04. La table utilise donc des
**temps relatifs** : `T0` = première tentative de login, `T1` = début de la phase SQLi
(connexion de session). Les offsets sont bornés par la boucle `curl` de 10 tentatives, la
fenêtre `frequency=5 / timeframe=60` et le dwell `< 2 s`. Aucune seconde absolue n'est inventée.

| # | Temps relatif | Étape | Requête / événement | Résultat | Détection |
| - | ------------- | ----- | ------------------- | -------- | --------- |
| 1 | `T0` | Début de la force brute | `POST /login`, `email=admin@supportdesk.local`, `password=WRONG_1` | 302, `event.outcome=failure` | `100110` (niveau 3) |
| 2 | `T0+<1 s` | Tentatives 2 à 5 | `POST /login`, `password=WRONG_2` … `WRONG_5` | 302, échec | `100110` (échecs suivants) ; seuil 5/60 s atteint |
| 3 | `T0+~1 s` | Corrélation brute force | Agrégation `frequency=5`, `timeframe=60`, `same_field=source.ip` | 5 échecs sur la même source | **`100111`** (niveau 10) |
| 4 | `T0+~1 s` | Tentatives 6 à 10 | `POST /login`, `password=WRONG_6` … `WRONG_10` | 302, échec | Cumul §8 : **9 × `100110`** pour 10 tentatives |
| 5 | `T0+~2 s` | Ingestion et indexation | Alertes custom de la phase 1 | Indexer green | **`< 2 s`** de dwell |
| 6 | `T1` | Connexion de session pour la phase 2 | `POST /login`, `email=jdupont@supportdesk.local`, `password=User_123` | 302 vers `/dashboard`, `event.outcome=success` | Aucune (trafic légitime) |
| 7 | `T1+<1 s` | Tentative d'injection SQL | `POST /tickets/search`, corps `search=%27%20OR%20%271%27%3D%271` | 200, `event.outcome=success` | Motif SQLi dans `http.request.body` |
| 8 | `T1+<1 s` | Alerte SQLi | Règle 100121 sur le corps décodé `' OR '1'='1` | 1 alerte custom | **`100121`** (niveau 10) |
| 9 | `T1+<2 s` | Ingestion et indexation | Alerte custom de la phase 2 | Indexer green | **`< 2 s`** de dwell |

**Décompte final (RB-04 §8, reproduit tel quel) :** 10 tentatives de login → 9 × `100110`
(niveau 3) + 1 × `100111` (niveau 10) ; 1 requête SQLi authentifiée → 1 × `100121`
(niveau 10) ; aucune autre alerte custom. Le rapport de qualification §10 confirme
**11 alertes custom, exactement celles attendues par la scène**.

## 3. Indicateurs de compromission (IOCs)

| Type | Indicateur | Contexte | Source |
| ---- | ---------- | -------- | ------ |
| IP source | `::ffff:172.18.0.1` (bridge Docker) | **IP interne au laboratoire**, non routable ; la même machine héberge l'application, l'attaquant et la stack de détection. Sans `X-Forwarded-For`, `source.ip` prend l'adresse du bridge Docker. | [dashboard.md](dashboard.md) §6 ; [RB-01](../../detection/runbooks/RB-01-bruteforce.md) §5 |
| Compte ciblé (brute force) | `admin@supportdesk.local` | Compte administrateur valide, ciblé par 10 tentatives successives | [RB-04](../../detection/runbooks/RB-04-demo.md) §3 |
| Compte utilisé (session SQLi) | `jdupont@supportdesk.local` | Compte utilisateur légitime, session ouverte avant l'injection | [RB-04](../../detection/runbooks/RB-04-demo.md) §5 |
| Motifs de mots de passe | `WRONG_1` … `WRONG_10` | Série de 10 échecs consécutifs ; aucun mot de passe valide | [RB-04](../../detection/runbooks/RB-04-demo.md) §3 ; [RB-01](../../detection/runbooks/RB-01-bruteforce.md) §5 |
| Charge utile SQLi (brute) | `' OR '1'='1` | Neutralise la clause `LIKE` de la recherche de tickets | [RB-03](../../detection/runbooks/RB-03-sql-injection.md) §2 |
| Charge utile SQLi (encodée) | `%27%20OR%20%271%27%3D%271` | Forme percent-encodée envoyée dans `search=` ; décodée une fois avant journalisation | [RB-04](../../detection/runbooks/RB-04-demo.md) §5 ; contrat §4.1 |
| Endpoint ciblé (auth) | `POST /login` | Formulaire de connexion, pas de limitation de tentatives | [RB-01](../../detection/runbooks/RB-01-bruteforce.md) §3 |
| Endpoint ciblé (SQLi) | `POST /tickets/search` | Champ `search` concaténé dans la requête SQL (vulnérabilité volontaire D-005) | [RB-03](../../detection/runbooks/RB-03-sql-injection.md) §2 |
| Règle déclenchée | `100110`, niveau 3, MITRE T1110 | Échec de login unitaire | [100110_bruteforce.xml](../../detection/rules/100110_bruteforce.xml) |
| Règle déclenchée | `100111`, niveau 10, MITRE T1110.001 | Corrélation brute force (5 échecs / 60 s / même `source.ip`) | [100110_bruteforce.xml](../../detection/rules/100110_bruteforce.xml) |
| Règle déclenchée | `100121`, niveau 10, MITRE T1190 | Motif d'injection SQL dans `http.request.body` | [100120_sql_injection.xml](../../detection/rules/100120_sql_injection.xml) |
| Corrélation de requête | `trace.id` | Un identifiant par requête HTTP ; aucune valeur particulière n'est consignée dans RB-04 §8 | Contrat §4 |

Les URL et la charge utile sont **identiques à celles des runbooks** : la scène est rejouable.
L'IP source est une valeur de laboratoire, pas un indicateur de production.

## 4. Chaîne de détection

Chaque étape de l'attaque laisse une trace dans un champ précis du journal JSONL, puis est
qualifiée par une règle custom, puis visualisée dans un panneau.

### 4.1 Brute force -- de l'événement à l'alerte

| Étape | Champ porteur de la preuve | Valeur observée | Règle | Panneau |
| ----- | -------------------------- | --------------- | ----- | ------- |
| Échec unitaire | `event.category` / `event.action` / `event.outcome` | `authentication` / `login` / `failure` | `100110` | *Alertes par type d'événement* (`data.event.action=login`) |
| Attribution | `user.name` | `admin@supportdesk.local` | `100110` | *Dernières alertes SupportDesk* |
| Attribution source | `source.ip` | `::ffff:172.18.0.1` | `100110`, puis `100111` via `same_field` | *Top sources (IP)* |
| Corrélation | 5 événements `100110` dans 60 s sur le même `source.ip` | Rafale de la boucle `curl` | `100111` | *Timeline des alertes par sévérité* (pic niveau 10) |
| Effet applicatif | `http.response.status_code` | `302` (le verdict réel est dans `event.outcome`, D-004) | -- | Grafana : *Auth attempts / s by outcome*, série `outcome="failure"` à **+10** |

Point clé : le statut HTTP reste `302` pour un échec comme pour un succès. La règle lit donc
`event.outcome`, posé par l'application (D-004), puis `100111` agrège les `100110` par `source.ip`.

### 4.2 Injection SQL -- de l'événement à l'alerte

| Étape | Champ porteur de la preuve | Valeur observée | Règle | Panneau |
| ----- | -------------------------- | --------------- | ----- | ------- |
| Requête injectée | `http.request.path` / `http.request.method` | `/tickets/search` / `POST` | -- | *Dernières alertes SupportDesk* |
| Charge utile | `http.request.body` | `search=%27%20OR%20%271%27%3D%271` (décodé : `search=' OR '1'='1`) | `100121` | Fiche d'alerte, champ `data.http.request.body` |
| Contexte session | `event.action` / `event.category` / `event.outcome` | `search` / `web` / `success` | -- | *Alertes par type d'événement* |
| Attribution source | `source.ip` | `::ffff:172.18.0.1` | `100121` | *Top sources (IP)* |
| Effet applicatif | `http.response.status_code` | `200` : la requête réussit, seule la détection la voit | -- | *Dernières alertes SupportDesk* (aucune erreur côté app) |

Le contrat impose `http.request.body` **après une seule URL-décodification** et sans échappement
(§4.1) : cette valeur décodée est reconnue par la regex `100121` (`or\s+1\s*=\s*1`, `'\s*or\s*'`).
`trace.id` relie la requête à son événement, mais aucune valeur de trace n'est archivée dans §8.

### 4.3 Vue d'ensemble

Le dashboard versionné **Sentinel X - Détection SupportDesk** filtre `rule.groups:supportdesk`
et affiche les deux alertes dans la même fenêtre. *Alertes par règle* montre `100111` et `100121`
au niveau 10 ; la *Timeline* montre le pic du brute force puis l'alerte SQLi isolée. Côté Grafana,
*Auth attempts / s by outcome* matérialise les 10 échecs sans dégrader les métriques.

## 5. Analyse et conclusion

### 5.1 Gravité

La scène combine deux vulnérabilités **volontaires** du projet scolaire :

- **Injection SQL sur `/tickets/search`** (T1190, D-005) : le champ `search` est concaténé dans
  la clause `LIKE`, sans requête paramétrée. RB-03 démontre qu'un dump complet de la table
  `users` est possible, avec **mots de passe en clair**.
- **Politique de mots de passe faible et absence de limitation** (T1110) : 10 tentatives
  successives sont acceptées sans verrouillage ni ralentissement. Aucun mot de passe n'a été
  trouvé pendant la démo, mais la surface reste ouverte.

La gravité théorique est donc **élevée** (compromission possible de la base d'authentification).
Dans la démo, la gravité opérationnelle est **nulle** : laboratoire isolé, attaque autorisée et
documentée, aucune donnée réelle. L'application doit rester vulnérable pour la démonstration.

### 5.2 Ce que les défenseurs ont bien fait

- **Corrélation plutôt que seuil unitaire :** `100111` a transformé 9 échecs isolés (niveau 3,
  faciles à ignorer) en une alerte de niveau 10 en moins de 2 secondes. Une alerte unitaire
  seule n'aurait pas distingué une faute de frappe d'une attaque.
- **Détection sans impact :** les deux attaques ont été vues alors que l'application répondait
  normalement (302 / 200) et que Grafana restait alimenté.
- **Absence de faux positif :** 0 alerte custom sur 1058 requêtes normales le 2026-10-30,
  confirmé par 0 alerte sur 1043 requêtes le 2026-10-31 avec l'outil corrigé.
- **Traçabilité complète :** payload, compte, IP source et `trace.id` sont conservés.

### 5.3 Risques résiduels

- **Force brute lente :** moins de 5 tentatives par minute reste sous le seuil de `100111`
  (chaque échec produit seulement un `100110`).
- **Rotation d'IP :** `source.ip` provient de `X-Forwarded-For`, contrôlable par le client ;
  une rotation contourne la corrélation par `same_field source.ip` (contrat §4.2).
- **Mots de passe en clair :** un dump SQLi donne un accès immédiat à tous les comptes, dont
  deux administrateurs (RB-03 §3).
- **Injection non corrigée par conception :** le correctif applicatif ne peut pas être appliqué
  sans casser la démonstration ; la détection reste la seule barrière.

### 5.4 Recommandations

1. **Limiter `/login`** : rate-limiting par IP et par compte, puis verrouillage progressif.
2. **Requêtes paramétrées** pour `/tickets/search` (correctif hors build de démonstration).
3. **Hacher les mots de passe** (bcrypt/argon2) et retirer les secrets en clair de la base.
4. **Durcir la corrélation** : volume d'échecs par compte, indépendamment de l'IP.

## 6. Traçabilité

| Document | Rôle | Lien |
| -------- | ---- | ---- |
| RB-04 -- démo live | Scénario exécuté ; §8 = résultats de référence du 2026-10-30 | [RB-04](../../detection/runbooks/RB-04-demo.md) |
| RB-01 -- brute force | Méthodologie et observations de la force brute | [RB-01](../../detection/runbooks/RB-01-bruteforce.md) |
| RB-03 -- injection SQL | Méthodologie et preuve d'exploitation SQLi | [RB-03](../../detection/runbooks/RB-03-sql-injection.md) |
| Rapport de qualification §10 | Décompte des 11 alertes custom de la scène | [alert-qualification-report.md](alert-qualification-report.md) |
| Rapport FP du 2026-10-30 | Fenêtre 600 s, 1058 requêtes normales, 0 alerte custom | [fp-report-20261030T121715.json](../../detection/tests/fp-report-20261030T121715.json) |
| Rapport FP du 2026-10-31 | Fenêtre 600 s, 1043 requêtes, 0 alerte custom, contrôle positif 100121 en 1,5 s | [fp-report-20261031T134550.json](../../detection/tests/fp-report-20261031T134550.json) |
| Contrat §4 | Champs JSONL : `event.action`, `event.outcome`, `http.request.body`, `source.ip`, `user.name`, `trace.id` | [CONTRACT.md](../../CONTRACT.md) |
| Règles 100110 / 100111 | Définitions des règles brute force | [100110_bruteforce.xml](../../detection/rules/100110_bruteforce.xml) |
| Règle 100121 | Définition de la règle SQLi (corps de requête) | [100120_sql_injection.xml](../../detection/rules/100120_sql_injection.xml) |
| Dashboard de détection | Panneaux et filtres utilisés en §4 | [dashboard.md](dashboard.md) |

**Conclusion.** L'incident RB-04 du 2026-10-30 est **entièrement reconstruit** à partir des
alertes et des journaux : deux phases (force brute puis injection SQL), 11 alertes custom
attendues et observées, dwell inférieur à 2 secondes, aucun faux positif. La détection a tenu
son rôle sans impacter l'application. Les vulnérabilités exploitées sont volontaires ; les
recommandations ci-dessus décrivent les correctifs à appliquer hors contexte de démonstration.
