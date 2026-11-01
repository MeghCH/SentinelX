# Playbooks de triage des alertes SupportDesk

Ce dossier contient un playbook opérationnel par famille de règles custom Wazuh
(`100100`-`100161`) : ce que l'alerte signifie, comment la qualifier et quelle action prendre.
Ils s'appuient sur le [dashboard de détection](../dashboard.md), le
[rapport de qualification](../alert-qualification-report.md) et les runbooks d'attaque.

| Playbook                                                        | Règles         | Objet                                                          |
| --------------------------------------------------------------- | -------------- | -------------------------------------------------------------- |
| [Brute force](TRIAGE-bruteforce.md)                             | 100110, 100111 | Échecs de login répétés et corrélation par IP.                 |
| [Injection SQL](TRIAGE-sql-injection.md)                        | 100120, 100121 | Motifs SQLi dans la query string ou le corps de requête.       |
| [SSRF](TRIAGE-ssrf.md)                                          | 100130         | Appel `/admin/fetch` vers une cible interne ou des métadonnées.|
| [Path traversal](TRIAGE-path-traversal.md)                      | 100140, 100141 | Tentative et réussite de lecture hors de `public/kb`.          |
| [IDOR](TRIAGE-idor.md)                                          | 100150, 100151 | Export de tickets non possédés et énumération.                 |
| [Scan d'endpoints](TRIAGE-scan.md)                              | 100160, 100161 | Rafale de réponses 4xx depuis une même IP.                     |
| [Événements de base](TRIAGE-other-supportdesk-events.md)        | 100100         | Règle parente : tout événement applicatif SupportDesk.         |

Chaque playbook cite au moins un identifiant de règle présent dans
`detection/rules/*.xml` et renvoie au test ou au runbook correspondant.
