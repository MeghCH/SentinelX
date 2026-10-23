# Runbook RB-01 - Brute force on /login

- **Scénario :** attaque par force brute sur l'authentification
- **Attack plan de référence :** `detection/attack-plans/AP-01-bruteforce.md`
- **Règles de détection :** 100110 (échec unitaire), 100111 (corrélation brute force)
- **Date d'exécution :** 22-10-2026
- **Opérateur :** Meghan CRESCI-HUMANN
- **Cible :** SupportDesk V1 - `http://127.0.0.1:3000/login`
- **MITRE ATT&CK :** T1110.001 - Password Guessing

> Un runbook est reproductible : en suivant les commandes ci-dessous, n'importe quel membre
> de l'équipe rejoue l'attaque et obtient les mêmes alertes.

---

## 1. Pré-requis

- Wazuh et SupportDesk démarrés :
  ```bash
  docker ps | grep -E "supportdesk|wazuh.manager"
  ```
- hydra installé (`hydra -h`).
- Liste de mots de passe de test :
  ```bash
  cat > /tmp/passwords.txt << 'LIST'
  123456
  password
  admin
  letmein
  qwerty
  root
  toor
  admin123
  password1
  welcome
  LIST
  ```

## 2. Mesure (avant/après)

Le fichier `alerts.json` cumule les alertes : on compte avant et après, et on fait la différence.

```bash
# AVANT
docker exec sentinelx-wazuh.manager-1 grep -c '"id":"100111"' /var/ossec/logs/alerts/alerts.json
```

## 3. Commandes d'attaque

**Variante A - parallèle (rafale, 10 tâches simultanées) :**

```bash
hydra -l admin@techco.local -P /tmp/passwords.txt \
  -s 3000 127.0.0.1 http-post-form \
  "/login:email=^USER^&password=^PASS^:Invalid credentials" \
  -V
```

**Variante B - séquentiel (une tentative à la fois) :**

```bash
hydra -l admin@techco.local -P /tmp/passwords.txt \
  -s 3000 127.0.0.1 http-post-form \
  "/login:email=^USER^&password=^PASS^:Invalid credentials" \
  -t 1 -V
```

Explication du format : `^USER^` / `^PASS^` sont remplacés par hydra ; `Invalid credentials` est la chaîne qui marque un échec (permet à hydra de savoir qu'une tentative a raté).

## 4. Mesure après et vérification

```bash
sleep 20
docker exec sentinelx-wazuh.manager-1 grep -c '"id":"100110"' /var/ossec/logs/alerts/alerts.json
docker exec sentinelx-wazuh.manager-1 grep -c '"id":"100111"' /var/ossec/logs/alerts/alerts.json
```

Dashboard : Threat Hunting -> Events -> `rule.id:100111`.

---

## 5. Observations (exécution du 2026-10-22)

### Déroulé

| Variante                  | Durée des 10 tentatives     | Alertes 100111 (avant -> après) | Delta  |
| ------------------------- | --------------------------- | ------------------------------- | ------ |
| A - parallèle (10 tâches) | ~1 s (16:04:16 -> 16:04:17) | 1 -> 3                          | **+2** |
| B - séquentiel (`-t 1`)   | ~3 s (16:05:49 -> 16:05:52) | 3 -> 4                          | **+1** |

- Les 10 tentatives ont généré des alertes **100110** (échec unitaire, niveau 3) pour chaque essai, puis des alertes **100111** (brute force, niveau 10) par paliers de corrélation.
- hydra n'a trouvé aucun mot de passe valide (`0 valid password found`) : l'attaque échoue fonctionnellement, mais **est bien détectée**.
- Aucun `X-Forwarded-For` n'étant envoyé par hydra, toutes les requêtes portent l'IP du bridge Docker : du point de vue de la corrélation, elles proviennent de la même source (ce qui ici **favorise** la détection), mais la véritable IP de l'attaquant n'apparaît pas.

### Alerte obtenue (100111)

- Règle : 100111, niveau 10
- Description : « possible brute force on /login »
- Groupes : `supportdesk, authentication_failures`
- MITRE : T1110.001 (Credential Access / Password Guessing)

![Alerte brute force hydra](../img/RB-01-100111.png)

---

## 6. Analyse

- **Succès de détection :** l'attaque est détectée dans les deux modes. Critère de succès de AP-01 (alerte niveau ≥ 10, règle 100111) **atteint**.
- **Effet du rythme sur la corrélation :** le mode parallèle a produit plus d'alertes (+2) que le séquentiel (+1), bien qu'il soit plus rapide. La corrélation `frequency=5 / timeframe=60` déclenche à plusieurs paliers selon la façon dont les requêtes se groupent à la lecture. Cela rejoint la limite étudiée en **T-005** : le comptage dépend du rythme d'arrivée des événements, pas seulement de leur nombre.
- **Détection non ralentie :** contrairement à la micro-rafale de T-005 (5 événements simultanés -> 0 alerte), un hydra réaliste (10 tentatives sur 1 à 3 s) est correctement détecté.

## 7. Limites et pistes d'amélioration

- **Évasion par ralentissement :** un attaquant envoyant moins de 5 tentatives par minute reste sous le seuil de 100111 (chaque échec déclenche tout de même 100110). -> scénario d'évasion bonus : brute force lent.
- **Évasion par rotation d'IP :** avec un vrai reverse proxy et un `X-Forwarded-For` tournant, la corrélation `same_field source.ip` serait contournée. -> documenté comme vecteur d'évasion (contrat §4.2).
- **Seuil à valider :** le seuil de 5/60 s devra être confirmé contre le script de trafic normal (étape 3) pour éviter les faux positifs sur des fautes de frappe d'utilisateurs légitimes.

## 8. Statut

| Critère (AP-01)                                      | Résultat                 |
| ---------------------------------------------------- | ------------------------ |
| Alerte sévérité ≥ 10, règle 100111                   | ✅                       |
| Détection < 2 min                                    | ✅ (quelques secondes)   |
| Attaque fonctionnellement bloquée (aucun mdp trouvé) | ✅                       |
| Reproductible                                        | ✅ (commandes ci-dessus) |

**Conclusion : scénario validé.** La règle de détection brute force fonctionne contre un outil d'attaque réel (hydra).
