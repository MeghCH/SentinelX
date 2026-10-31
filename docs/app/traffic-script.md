# SupportDesk — Script de trafic réaliste (contrat §10)

**Branche :** `feat/W02-traffic-script` — 2026-10-22
**Objet :** trafic de référence normal, enregistré pour mesurer le taux de faux positifs côté Wazuh.
**Script :** `supportdesk/scripts/traffic.js` — Node ≥ 20 stdlib, **zéro dépendance**.

## Spécification §10

| Élément               | Valeur agée (à valider par l'équipe, §12)                                        |
| --------------------- | -------------------------------------------------------------------------------- |
| Cible                 | `supportdesk` (défaut `--base http://127.0.0.1:3000`, surchargeable)              |
| Outil                 | Node stdlib (fetch) — script versionné dans le repo                               |
| Durée                 | **600 s** par défaut (`--duration N`), proposition : ≥ 10 min par mesure FP      |
| Volume                | ~700–900 requêtes / 10 min : 6 employés + 1 admin, temps de réflexion 2–6 s      |
| Adresses source       | Une IP LAN fixe par identité (`10.20.0.11`–`10.20.0.20`) envoyée en `X-Forwarded-For` (`trust proxy`, D-010) ; `--sameIp` pour tout envoyer depuis l'IP de la machine |
| Comportement normal   | login → consultation tickets/filtres, recherche vocabulaire innocent, KB, commentaire, profil, export de tickets **possédés**, admin : `/admin`, `/admin/fetch` (URL publique), export de tout ticket (légal pour ce rôle) |
| Alertes attendues     | **ZÉRO** (configuration par défaut). Variante `--typos N` : exactement autant d'alertes 100110 que de typos placées (`failedLogins` du rapport, ≤ N), documentées comme faux positifs de référence |

## Table de justification (pourquoi chaque règle ne doit pas se déclencher)

| Règle                  | Pourquoi le trafic normal ne la déclenche pas                                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `100110` login failure | Les échecs de login par défaut = 0. Variante `--typos N` : échecs **espacés d'au moins 90 s** (tous utilisateurs confondus) → une alerte de niveau 3 par typo placée |
| `100111` brute force   | 5 échecs / 60 s / même IP requis ; avec l'espacement de 90 s, il y a au plus 1 échec par fenêtre de 60 s, quelle que soit l'IP           |
| `100120/121` SQLi      | Le vocabulaire de recherche est auto-vérifié contre le pcre2 de la règle au démarrage du script (abort sinon)                                   |
| `100130` SSRF          | La seule requête `/admin/fetch` utilise `https://status.example.com/health` (URL publique, comme le sample `fetch_normal.jsonl`)               |
| `100140` traversal     | `/kb/view` ne demande que les 3 documents légitimes de `public/kb/`                                                                             |
| `100150` IDOR          | Les exports utilisateur = tickets possédés (carte dérivée de `database/seed.js`) ; l'admin est exclu par la négation de `user.role`             |
| `100160/161` scan      | **0 réponse 4xx** sur le cycle complet → `100160` (level 4, par event 4xx) ne voit rien du tout                                                |

## Méthode de mesure des faux positifs (§10)

```text
taux de faux positifs = faux positifs / total d'alertes
```

Pendant la durée convenue, enregistrer : le volume du trafic (rapport JSON produit par le script), la période, puis classer chaque alerte Wazuh (vrai/faux positif + justification). Les seules alertes autorisées a priori sont les `100110` des typos en mode `--typos` (référence de FP assumée). Le champ `sourceIps` du rapport donne l'IP de chaque identité, ce qui permet de rattacher une alerte au trafic normal. Périmètre : les alertes custom `100100`-`100199` ; sur une fenêtre purement normale le ratio vaut `0 / 0` si la chaîne reste muette, le résultat est donc aussi exprimé en faux positifs pour 1000 requêtes (cf. §1 du [rapport de qualification](../detection/alert-qualification-report.md)).

## Usage

```bash
# Trafic de référence standard (10 min, 0 false positif attendu)
node scripts/traffic.js --base http://127.0.0.1:3000 --duration 600

# Variante avec 2 typos (test du seuil de la règle brute force)
node scripts/traffic.js --duration 600 --typos 2 --verbose

# Tout le trafic depuis l'IP de la machine (pas de X-Forwarded-For)
node scripts/traffic.js --duration 600 --sameIp

# Le rapport JSON (requêtes, endpoints, statuts, sessions, IP source) est écrit à la fin
```

## Garde-fous intégrés

- Auto-vérification anti-injection du vocabulaire à chaque démarrage (les regex de `100120` dupliquées en JS).
- Garde-fou anti-URL interne sur `--fetchUrl` (patterns de `100130`).
- Abort si l'application ne répond pas au démarrage.
- Typos réservées de façon atomique (avant tout `await`) et espacées d'au moins 90 s : les workers qui démarrent en même temps ne peuvent pas échouer ensemble. Si la durée ne permet pas de placer les N typos, le rapport le signale.

## Notes

- La carte des tickets possédés reflète `database/seed.js` (42 tickets, ids 1–42) ; la mettre à jour si la seed change.
- Pas d'adresse d'expéditeur suspecte : user-agent navigateur plausible (Chrome sous Windows) sur chaque requête.
- Les sessions sont réelles (cookies) : quelques re-login/logout par employé pendant la durée.
- **HTTP 500 attendus** : le terme `probleme d'impression` du vocabulaire de recherche contient une apostrophe qui casse la requête SQL volontairement injectable de `POST /tickets/search` (≈ 1 recherche sur 9 → 500 + événement `internal_error`). C'est le symptôme fonctionnel de la vulnérabilité d'AP-03 (D-005), conservé exprès : il prouve qu'une apostrophe légitime ne déclenche pas `100121`. Aucune règle custom ne cible les 5xx. Détail : §6 du [rapport de qualification](../detection/alert-qualification-report.md).