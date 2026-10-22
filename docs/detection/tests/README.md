# Tests de détection

| ID                                           | Objet                                                                  | Règle(s)             | Résultat                                     | Date       |
| -------------------------------------------- | ---------------------------------------------------------------------- | -------------------- | -------------------------------------------- | ---------- | --- | ---------- | --- | ---------- |
| [T-001](T-001-json-decoder-compat.md)        | Compatibilité du schéma avec le décodeur JSON natif                    | 1002 (native)        | ✅                                           | 2026-10-15 |
| [T-002](T-002-rule-100110-login-failure.md)  | Échec de login unitaire                                                | 100100, 100110       | ✅                                           | 2026-10-15 |
| [T-003](T-003-rule-100111-bruteforce.md)     | Brute force par IP sur /login (wazuh-logtest)                          | 100110, 100111       | ✅ (seuil provisoire)                        | 2026-10-15 |
| [T-004](T-004-end-to-end-chain.md)           | Chaîne fichier → Wazuh → dashboard                                     | 100100, 100110       | ✅ après 2 corrections du format             | 2026-10-16 |
| [T-005](T-005-correlation-burst.md)          | Corrélation brute force : rafale vs espacé                             | 100110, 100111       | ⚠️ limite identifiée                         | 2026-10-16 |
| [T-006](T-006-new-contract-fields.md)        | Nouveaux champs du contrat v0.3.0 (query, body, owner)                 | 100100, 100110       | ✅ (indexation complétée par T-007 et T-008) | 2026-10-19 |
| [T-007](T-007-rule-100140-path-traversal.md) | Path traversal sur /kb/view (tentative, succès, cas normal)            | 100140, 100141       | ✅                                           | 2026-10-19 |
| [T-008](T-008-rule-100150-idor.md)           | IDOR sur l'export de tickets (accès isolé, énumération, cas légitimes) | 100150, 100151       | ✅                                           | 2026-10-20 |
| [T-009](T-009-rule-100120-sql-injection.md)  | Injection SQL (URL, corps, recherche normale, apostrophe)              | 100120, 100121       | ✅                                           | 2026-10-20 |
| [T-010](T-010-rule-100130-ssrf.md)           | SSRF sur /admin/fetch (métadonnées, localhost, fetch externe)          | 100130               | ✅                                           | 2026-10-20 |
| [T-011](T-011-rule-100160-scan.md)           | Scan d'endpoints (404 isolée, rafale de 4xx)                           | 100160, 100161       | ✅                                           | 2026-10-20 |
| [T-012](T-012-native-rules-training-logs.md) | Règles natives Wazuh sur logs d'entraînement SSH (secrepo)             | 5710, 5712 (natives) | ✅                                           | 2026-10-20 |
| [T-013](T-013-dry-run-real-app.md)           | Dry-run : chaîne complète sur l'application réelle                     | 100110, 100111       | ✅                                           | 2026-10-22 |     | 2026-10-20 |     | 2026-10-20 |

Nous pouvons rejouer les tests avec ce script -> run.sh.

- Une seule fois, pour le rendre exécutable : `chmod +x detection/tests/run.sh`.
- Les tests T-004 et T-005 peuvent être rejoués automatiquement (depuis la racine du repo, Wazuh démarré) :

```bash
chmod +x detection/tests/run.sh      # une seule fois
./detection/tests/run.sh             # tous les tests (~3 min 30)
./detection/tests/run.sh t004        # seulement T-004 (~20 s)
./detection/tests/run.sh t005        # seulement T-005 (~2 min)
```
