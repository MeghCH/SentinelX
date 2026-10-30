# Detection tests

| ID                                          | Object                                        | Rule(s)       | Result | Date       |
| ------------------------------------------- | --------------------------------------------- | ------------- | ------ | ---------- |
| [T-001](../../detection/tests/T-001-json-decoder-compat.md)       | Schema compatibility with the JSON decoder | 1002 (native) | ✅   | 2026-10-15 |
| [T-002](../../detection/tests/T-002-rule-100110-login-failure.md) | Single login failure                       | 100110        | ⏳     |            |
| [T-003](../../detection/tests/T-003-rule-100111-bruteforce.md)    | Brute force by IP                          | 100111        | ⏳     |            |

# Collaboration convention

Any contribution to this GitHub repository **must** follow the [collaboration convention](../../COLLABORATION-CONVENTION.md).
Any action that does not follow this convention will be rejected from the project.

---

# Documentation map (FR ↔ EN)

The repository keeps its original French documentation and provides the same documents in English under `docs/en/`, mirroring the exact same paths. This table lists every documentation file of the repository and where each language lives.

| Document                                  | French (original)                                   | English (mirror)                                                     |
| ----------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------- |
| Contract (CONTRACT.md)                    | [CONTRACT.md](../../CONTRACT.md)                    | English original                                                     |
| Collaboration convention                  | [COLLABORATION-CONVENTION.md](../../COLLABORATION-CONVENTION.md) | English original                                          |
| Repository README                         | [README.md](../../README.md)                        | [docs/en/README.md](README.md)                                       |
| Wazuh environment setup                   | [docs/detection/setup.md](../detection/setup.md)    | [docs/en/detection/setup.md](detection/setup.md)                     |
| Wazuh dashboard                           | [docs/detection/dashboard.md](../detection/dashboard.md) | [docs/en/detection/dashboard.md](detection/dashboard.md)         |
| Alert qualification report                | [docs/detection/alert-qualification-report.md](../detection/alert-qualification-report.md) | [docs/en/detection/alert-qualification-report.md](detection/alert-qualification-report.md) |
| Logging design (application)              | English original                                     | [docs/app/logging-design.md](app/logging-design.md)                  |
| Traffic script spec                       | [docs/app/traffic-script.md](../app/traffic-script.md) | [docs/en/app/traffic-script.md](app/traffic-script.md)           |
| Attack plans AP-01–AP-03                  | [detection/attack-plans/](../../detection/attack-plans/AP-01-bruteforce.md) | English original                            |
| Runbooks RB-01–RB-03                      | [detection/runbooks/](../../detection/runbooks/RB-01-bruteforce.md) | [docs/en/detection/runbooks/](detection/runbooks/RB-01-bruteforce.md) |
| Detection tests index                     | [docs/detection/tests/README.md](../detection/tests/README.md) | [docs/en/detection/tests/README.md](detection/tests/README.md) |
| Tests T-001 … T-013                       | [docs/detection/tests/](../detection/tests/)        | [docs/en/detection/tests/](detection/tests/)                         |
| Metrics design (application)              | English original                                    | [docs/app/metrics-design.md](app/metrics-design.md)                  |
| Endpoint map (SupportDesk)                | English original                                    | [docs/detection/Endpoints.md](../../detection/Endpoints.md)          |
| Monitoring — Prometheus config            | [monitoring/README.md](../../monitoring/README.md)  | [docs/en/monitoring/prometheus-configuration.md](monitoring/prometheus-configuration.md) |
| Monitoring — consolidated stack           | [docs/app/monitoring-stack.md](../app/monitoring-stack.md) | [docs/en/app/monitoring-stack.md](app/monitoring-stack.md)     |
| Non-functional tests                      | [docs/app/nonfunctional-tests.md](../app/nonfunctional-tests.md) | [docs/en/app/nonfunctional-tests.md](app/nonfunctional-tests.md) |