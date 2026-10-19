# Environnement de détection - installation et utilisation

Ce guide permet à n'importe quel membre de l'équipe de lancer l'environnement Wazuh du projet et de vérifier qu'il fonctionne, en partant d'un clone du repo.

- **Version :** Wazuh 4.14.9, déploiement single-node (manager, indexer, dashboard)
- **Origine :** fichiers adaptés de [wazuh-docker](https://github.com/wazuh/wazuh-docker) (tag `v4.14.9`, dossier `single-node`)
- **Durée :** environ 15 min la première fois (téléchargement des images)

Toutes les commandes se lancent **depuis la racine du repo**, sauf indication contraire.

---

## 1. Prérequis

| Élément                    | Requis                                | Vérification                                      |
| -------------------------- | ------------------------------------- | ------------------------------------------------- |
| Docker + Docker Compose v2 | oui                                   | `docker --version && docker compose version`      |
| RAM allouée à Docker       | 8 Go recommandés (6 Go minimum)       | Docker Desktop -> Settings -> Resources -> Memory |
| `vm.max_map_count`         | ≥ 262144                              | voir ci-dessous                                   |
| Ports libres               | 443, 9200, 55000, 1514, 1515, 514/udp | `ss -tulpn`                                       |
| Python 3                   | pour le script de tests               | `python3 --version`                               |

### `vm.max_map_count`

L'indexer refuse de démarrer si cette valeur est trop basse.

**Docker Engine (Linux natif) :**

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf   # persistant
```

**Docker Desktop :** les conteneurs tournent dans une VM qui a son propre noyau. Vérifier la valeur vue par les conteneurs :

```bash
docker run --rm --privileged alpine sysctl vm.max_map_count
```

Si elle est inférieure à 262144 :

```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

Ce réglage est perdu à chaque redémarrage de Docker Desktop.

---

## 2. Organisation des fichiers

```
detection/
├── logs/                      # volume lu par Wazuh (app.jsonl, non versionné)
├── rules/local_rules.xml      # règles custom, montées dans le manager
├── samples/                   # échantillons de logs conformes au contrat
├── tests/run.sh               # rejeu automatique des tests
└── wazuh/
    ├── docker-compose.wazuh.yml
    ├── generate-indexer-certs.yml
    └── config/
        ├── certs.yml
        ├── wazuh_cluster/wazuh_manager.conf   # contient le <localfile> de l'app
        ├── wazuh_dashboard/
        ├── wazuh_indexer/
        └── wazuh_indexer_ssl_certs/           # généré, jamais versionné
```

Modifications par rapport aux fichiers officiels :

- `docker-compose.wazuh.yml` : `name: sentinelx` (noms de conteneurs prévisibles) et deux montages dans `wazuh.manager` :
  - `../rules/local_rules.xml` -> `/var/ossec/etc/rules/local_rules.xml`
  - `../logs` -> `/var/log/sentinelx` (lecture seule)
- `wazuh_manager.conf` : lecture de `/var/log/sentinelx/app.jsonl` au format `json`.

---

## 3. Première installation

### 3.1 Générer les certificats

Les certificats TLS ne sont pas versionnés : chaque membre génère les siens, une seule fois.

```bash
cd detection/wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
```

Le message `find: command not found` en fin d'exécution est **sans conséquence** (outil absent de l'image du générateur). Vérifier le résultat :

```bash
sudo ls detection/wazuh/config/wazuh_indexer_ssl_certs
```

Attendu : `admin.pem`, `admin-key.pem`, `root-ca.pem`, `root-ca.key`, `root-ca-manager.pem`, `root-ca-manager.key`, et un `.pem` + `-key.pem` pour `wazuh.indexer`, `wazuh.manager` et `wazuh.dashboard`.

> `sudo` est nécessaire : le générateur crée les fichiers en `root`.

### 3.2 Démarrer la stack

```bash
docker compose -f detection/wazuh/docker-compose.wazuh.yml up -d
docker ps
```

Attendu : trois conteneurs `Up` - `sentinelx-wazuh.manager-1`, `sentinelx-wazuh.indexer-1`, `sentinelx-wazuh.dashboard-1`.

Le démarrage complet prend 1 à 2 minutes.

### 3.3 Accéder au dashboard

- URL : `https://localhost` (certificat auto-signé : accepter l'avertissement)
- Identifiants par défaut : `admin` / `SecretPassword`

« Wazuh dashboard server is not ready yet » : attendre encore une minute.

### 3.4 Vérifier que le fichier de logs est surveillé

```bash
docker exec sentinelx-wazuh.manager-1 grep -i "sentinelx" /var/ossec/logs/ossec.log
```

Attendu : `Analyzing file: '/var/log/sentinelx/app.jsonl'`.

### 3.5 Valider l'installation

```bash
chmod +x detection/tests/run.sh
./detection/tests/run.sh t004
```

Attendu : 3 lignes `[PASS]`. L'installation est fonctionnelle.

Pour rejouer tous les tests (environ 3 min 30) : `./detection/tests/run.sh`. Détail des tests : [`tests/README.md`](tests/README.md).

---

## 4. Utilisation courante

### Voir les alertes du projet

Dashboard -> **Threat Hunting** -> onglet **Events** -> requête :

```
rule.groups:supportdesk
```

Autres requêtes utiles : `rule.id:100111` (brute force), `rule.level >= 10`.

La colonne `timestamp` est l'heure de **réception** par Wazuh, pas le `@timestamp` du log.

### Simuler des événements applicatifs

```bash
cat detection/samples/login_failure.jsonl >> detection/logs/app.jsonl
```

Règle impérative : **un objet JSON par ligne**, jamais indenté (voir `CONTRACT.md` §4).

### Modifier une règle

1. Éditer `detection/rules/local_rules.xml`.
2. Redémarrer le manager pour charger la nouvelle version :
   ```bash
   docker restart sentinelx-wazuh.manager-1
   ```
3. Vérifier l'absence d'erreur de chargement (après ~30 s) :
   ```bash
   docker exec sentinelx-wazuh.manager-1 tail -n 50 /var/ossec/logs/ossec.log | grep -iE "error|critical|warning"
   ```
4. Tester la règle avec une ligne d'échantillon :
   ```bash
   docker exec -it sentinelx-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
5. Relancer `./detection/tests/run.sh` pour vérifier que rien n'est cassé.

Plage d'identifiants réservée : `100100`–`100199` (voir `CONTRACT.md` §8).

### Arrêter / réinitialiser

```bash
# Arrêter (les données sont conservées)
docker compose -f detection/wazuh/docker-compose.wazuh.yml down

# Repartir de zéro (supprime alertes et données indexées)
docker compose -f detection/wazuh/docker-compose.wazuh.yml down -v
```

---

## 5. Diagnostic

Quand une alerte attendue n'apparaît pas dans le dashboard, vérifier dans cet ordre :

```bash
# 1. Le conteneur voit-il les lignes ? (1 ligne = 1 événement)
docker exec sentinelx-wazuh.manager-1 wc -l /var/log/sentinelx/app.jsonl

# 2. Les alertes sont-elles générées ?
docker exec sentinelx-wazuh.manager-1 grep -c "supportdesk" /var/ossec/logs/alerts/alerts.json

# 3. L'indexer les a-t-il refusées ?
docker logs --since 5m sentinelx-wazuh.manager-1 2>&1 | grep -iE "cannot index|mapper_parsing"
```

| Étape en échec     | Cause probable                                                                     |
| ------------------ | ---------------------------------------------------------------------------------- |
| 1 : 0 ligne        | montage du volume `detection/logs` incorrect                                       |
| 1 : trop de lignes | JSON indenté (un événement découpé en plusieurs lignes)                            |
| 2 : 0 alerte       | règle non chargée, champ mal nommé, ou JSON invalide (tester avec `wazuh-logtest`) |
| 3 : erreurs        | conflit de type avec le template Wazuh (ex. objet `url`, voir T-004)               |

---

## 6. Problèmes connus

| Symptôme                                                                 | Cause                                                                                                             | Solution                                                                                    |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `cp: cannot stat … wazuh_indexer_ssl_certs: Permission denied`           | certificats créés en `root`                                                                                       | ne pas copier les certificats : les régénérer (§3.1)                                        |
| `empty compose file` / `File //config.yml is empty`                      | fichier créé vide dans l'éditeur au lieu d'être copié                                                             | vérifier avec `find detection/wazuh -type f -empty`, recopier depuis wazuh-docker `v4.14.9` |
| Le manager ne démarre pas, chemin de config en dossier                   | fichier mal nommé (`wazuh-manager.conf` au lieu de `wazuh_manager.conf`) : Docker crée un dossier vide à la place | renommer avec un underscore                                                                 |
| L'indexer s'arrête au démarrage                                          | `vm.max_map_count` trop bas ou RAM insuffisante                                                                   | §1                                                                                          |
| Alertes dans `alerts.json` mais pas dans le dashboard                    | refus d'indexation (conflit de mapping)                                                                           | §5, étape 3                                                                                 |
| `alerts.json` vide le lendemain                                          | Wazuh archive ce fichier chaque nuit                                                                              | normal : l'historique reste dans le dashboard                                               |
| La règle brute force 100111 ne se déclenche pas pour une rafale d'échecs | corrélation peu fiable quand les événements arrivent groupés                                                      | limite connue, voir T-005                                                                   |
| Port 443 déjà utilisé                                                    | autre service local                                                                                               | modifier `443:5601` dans le compose (ex. `8443:5601`)                                       |

---

## 7. Sécurité

- Les identifiants par défaut (`admin` / `SecretPassword`, mots de passe de l'API) sont ceux de wazuh-docker : acceptables en lab local, **à changer** pour toute exposition hors de la machine.
- Les certificats (`wazuh_indexer_ssl_certs/`) et le fichier `.env` sont exclus de Git par `.gitignore`. Vérifier avant chaque push :
  ```bash
  git ls-files | grep -E "\.pem|\.key"     # ne doit rien afficher
  ```
