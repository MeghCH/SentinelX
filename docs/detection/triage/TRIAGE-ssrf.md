# Playbook de triage - SSRF sur /admin/fetch

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                            | MITRE |
| ------ | ------ | -------------------------------------------------------- | ----- |
| 100130 | 10     | `POST /admin/fetch` avec une URL interne dans le corps   | T1190 |

Fichier : `detection/rules/100130_ssrf.xml`.

## 2. Ce que l'alerte signifie

Un client disposant d'une session administrateur demande au serveur de récupérer une URL qui
pointe vers une ressource interne : `127.0.0.1`, `localhost`, `169.254.169.254` (métadonnées
cloud), un réseau privé `10.x`/`192.168.x`/`172.16-31.x`, ou un schéma `file://`, `gopher://`,
`dict://`. C'est une Server-Side Request Forgery : l'attaquant utilise le serveur comme proxy
pour atteindre des services non exposés ou voler des jetons de métadonnées.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100130`, puis vérifier la période et le contexte.
2. **Champs à lire** : `http.request.body` (URL demandée), `source.ip`, `user.name`,
   `user.role`, `security.indicator` (doit valoir `admin_area`), `http.response.status_code`.
3. **Journal applicatif** : `detection/logs/app.jsonl`, événement `event.action=request` sur
   `/admin/fetch` ; comparer l'URL demandée et le statut.
4. **Grafana** : panneaux *Statuts HTTP* et *taux d'erreurs* pour repérer une rafale de requêtes
   admin ou des erreurs de connexion côté serveur.
5. **Vrai positif** : URL ciblant une adresse interne, la métadonnée cloud ou un schéma non
   HTTP. L'utilisateur est administrateur (la règle ne couvre que les appels reçus par
   `/admin/fetch`).
6. **Faux positif** : URL publique légitime, par exemple `https://status.example.com/health`
   utilisée par le trafic normal (cf. [rapport de qualification](../alert-qualification-report.md)).
   Aucune règle ne doit se déclencher sur une destination publique.

## 4. Action selon verdict

**Vrai positif**

- Révoquer la session administrateur concernée et alerter l'astreinte.
- Couper l'accès sortant du serveur vers les métadonnées cloud et les réseaux internes non
  nécessaires (pare-feu egress / allowlist).
- Inspecter les journaux réseau du conteneur pour identifier les services contactés et les
  données récupérées.
- Auditer le compte admin : autres appels `/admin/*`, création d'utilisateurs, exports.

**Faux positif**

- Documenter l'URL publique et le besoin métier.
- Inscrire la destination dans une allowlist explicite si elle est récurrente, sans élargir le
  motif aux plages internes.

## 5. Lien

- Runbook : pas de runbook dédié ; scénario couvert par le test T-010 et le runbook de démo
  [RB-04](../../../detection/runbooks/RB-04-demo.md) pour la chaîne globale.
- Test : [T-010 - règle 100130](../tests/T-010-rule-100130-ssrf.md)
- Contexte : [dashboard de détection](../dashboard.md)
