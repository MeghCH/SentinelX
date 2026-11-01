# Playbook de triage - Scan d'endpoints (rafale de 4xx)

## 1. Règle(s)

| Règle  | Niveau | Déclenchement                                                  | MITRE       |
| ------ | ------ | -------------------------------------------------------------- | ----------- |
| 100160 | 4      | Réponse 4xx unitaire (parente : 100100)                        | —           |
| 100161 | 10     | 15 réponses 4xx / 30 s depuis la même `source.ip`              | T1595.003   |

Fichier : `detection/rules/100160_scan.xml`.

## 2. Ce que l'alerte signifie

Un client enchaîne les requêtes vers des chemins qui n'existent pas ou qui sont interdits, et
récolte des réponses 4xx (surtout 404). C'est la signature d'un outil de découverte de contenu
(ffuf, gobuster, dirb) qui cherche des pages cachées, des backups ou des endpoints non
documentés. 100160 journalise chaque erreur client ; 100161 corrèle la rafale par IP.

## 3. Comment vérifier (triage)

1. **Dashboard Wazuh** : filtre `rule.id:100161`, puis `rule.id:100160` pour la fenêtre.
   Le panneau *Top sources (IP)* met en évidence la source la plus active.
2. **Champs à lire** : `source.ip`, `http.request.path`, `http.request.method`,
   `http.response.status_code`, `user_agent.original` (UA d'outil souvent révélateur).
3. **Journal applicatif** : `detection/logs/app.jsonl`, compter les 4xx par `source.ip` et par
   chemin sur la fenêtre de 30 s.
4. **Grafana** : panneau *Statuts HTTP* ; une masse de 4xx depuis une IP confirme le scan.
5. **Vrai positif** : au moins 15 réponses 4xx en 30 s depuis une même IP, sur des chemins
   variés. Le trafic normal ne produit aucun 4xx (cf.
   [rapport de qualification](../alert-qualification-report.md)).
6. **Faux positif** : un utilisateur ou un client qui suit un lien obsolète et répète la même
   URL, ou un crawler légitime. Un seul chemin répété n'est pas un scan de wordlist.

## 4. Action selon verdict

**Vrai positif**

- Bloquer ou limiter l'IP source au niveau du reverse proxy.
- Vérifier si le scan a obtenu des réponses 2xx sur des chemins sensibles (`/admin`, exports,
  `.env`, backups) : si oui, escalader en incident.
- Relever l'IP, le user-agent, la liste des chemins testés et la fenêtre temporelle.
- Contrôler les alertes voisines (SSRF, IDOR, SQLi) : un scan précède souvent une exploitation.

**Faux positif**

- Documenter le lien obsolète ou le client légitime et la répétition d'un même chemin.
- Consigner le cas dans le [rapport de qualification](../alert-qualification-report.md).
- Ne pas ajouter d'exclusion large qui masquerait un vrai scan.

## 5. Lien

- Runbook : pas de runbook dédié ; scénario couvert par le test T-011.
- Test : [T-011 - règles 100160/100161](../tests/T-011-rule-100160-scan.md)
- Contexte : [dashboard de détection](../dashboard.md)
