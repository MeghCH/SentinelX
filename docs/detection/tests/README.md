# Tests de détection

# Tests de détection

| ID                                           | Objet                                                       | Règle(s)       | Résultat                         | Date       |
| -------------------------------------------- | ----------------------------------------------------------- | -------------- | -------------------------------- | ---------- |
| [T-001](T-001-json-decoder-compat.md)        | Compatibilité du schéma avec le décodeur JSON natif         | 1002 (native)  | ✅                               | 2026-10-15 |
| [T-002](T-002-rule-100110-login-failure.md)  | Échec de login unitaire                                     | 100100, 100110 | ✅                               | 2026-10-15 |
| [T-003](T-003-rule-100111-bruteforce.md)     | Brute force par IP sur /login (wazuh-logtest)               | 100110, 100111 | ✅ (seuil provisoire)            | 2026-10-15 |
| [T-004](T-004-end-to-end-chain.md)           | Chaîne fichier → Wazuh → dashboard                          | 100100, 100110 | ✅ après 2 corrections du format | 2026-10-16 |
| [T-005](T-005-correlation-burst.md)          | Corrélation brute force : rafale vs espacé                  | 100110, 100111 | ⚠️ limite identifiée             | 2026-10-16 |
| [T-006](T-006-new-contract-fields.md)        | Nouveaux champs du contrat v0.3.0 (query, body, owner)      | 100100, 100110 | ✅ décodage / ⏳                 |
| indexation partielle                         | 2026-10-19                                                  | identifiée     | 19-10-2026                       |
| [T-007](T-007-rule-100140-path-traversal.md) | Path traversal sur /kb/view (tentative, succès, cas normal) | 100140, 100141 | ✅                               | 2026-10-19 |

Nous pouvons rejouer les tests avec ce script -> run.sh.

- Une seule fois, pour le rendre exécutable : `chmod +x detection/tests/run.sh`.
- Puis, depuis la racine du repo : `./detection/tests/run.sh          # tous les tests (~3 min 30) ./detection/tests/run.sh t004     # seulement T-004 (~20 s) ./detection/tests/run.sh t005     # seulement T-005 (~2 min)`.
