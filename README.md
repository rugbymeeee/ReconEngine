# ReconEngine

Outil de reconnaissance réseau et d'audit de sécurité conçu pour tourner sur matériel embarqué personnalisé (PCB ARM64). Il découvre les hôtes actifs, scanne les ports/services en parallèle, corrèle les entrées Exploit-DB et génère des rapports PDF d'audit en français.

---

## Table des matières

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Usage CLI](#usage-cli)
- [Configuration](#configuration)
- [Modules](#modules)
- [Profils de scan](#profils-de-scan)
- [Rapport PDF](#rapport-pdf)
- [Matériel](#matériel)

---

## Fonctionnalités

- **Découverte d'hôtes** : ARP broadcast (Scapy) + nmap ping sweep en parallèle
- **Scan deux phases** (profil `full`) : détection TCP complète sur 65 535 ports → service/vulnérabilité sur les ports ouverts seulement
- **Scan rapide** (profil `quick`) : liste de ports ciblée sans scripts
- **Enrichissement Exploit-DB** : corrélation automatique via `searchsploit`, cache partagé entre terminal et rapport
- **Rapport PDF** : WeasyPrint + Jinja2, cartographie réseau matplotlib, score de risque global, plan d'action priorisé
- **Portée IoT/industriel** : MQTT, Modbus, RTSP, UPnP, AMQP couverts dans les ports par défaut

---

## Architecture

```
discover.py  ──→  scan.py (ThreadPoolExecutor)  ──→  rapport.py  ──→  PDF
    ↕                      ↕ cache partagé
 ARP + nmap           exploits.py (searchsploit)
```

### Pipeline en 4 phases

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `discover.py` | ARP broadcast + nmap ping sweep (parallèle) |
| 2 | `scan.py` | Scan ports/services (ThreadPoolExecutor) |
| 3 | `main.py` | Affichage terminal Rich avec exploits |
| 4 | `rapport.py` | Génération PDF WeasyPrint |

---

## Prérequis

- **Docker** (recommandé) — inclut nmap, searchsploit, dépendances système
- **Root** requis pour ARP (Scapy raw sockets) et nmap SYN scan (`-sS`)
- Python 3.12+ si exécution directe

---

## Démarrage rapide

```bash
# Via Docker Compose (recommandé)
cd docker
docker compose up --build

# Exécution directe (requiert root)
cd docker/tools
sudo python main.py
```

---

## Usage CLI

```
python main.py [PROFILE] [-t CIDR] [-i IFACE] [-o PATH] [--ports PORTS] [--workers N] [--timeout SEC]
```

### Arguments

| Argument | Description | Exemple |
|----------|-------------|---------|
| `PROFILE` | `quick` ou `full` (défaut : `full`) | `quick` |
| `-t`, `--target` | Réseau ou IP cible (CIDR) | `192.168.1.0/24` |
| `-i`, `--iface` | Interface réseau | `eth0` |
| `-o`, `--output` | Chemin du rapport PDF (doit rester sous le répertoire courant) | `rapports/audit.pdf` |
| `--ports` | Ports à scanner, format nmap | `22,80,443,8080` ou `1-1024` |
| `--workers` | Threads parallèles (défaut : 8) | `4` |
| `--timeout` | Délai découverte ARP en secondes (défaut : 5) | `10` |

### Exemples

```bash
# Scan rapide sur tout le réseau local
sudo python main.py quick

# Scan complet sur un sous-réseau ciblé
sudo python main.py full -t 192.168.1.0/24

# Ports personnalisés sur une interface spécifique
sudo python main.py -i eth0 --ports 22,80,443,8080

# Rapport vers un chemin personnalisé
sudo python main.py -o rapports/audit_prod.pdf

# Scan sans découverte (cible directe)
sudo python main.py full -t 10.0.0.5
```

> **Note** : passer `--ports` explicitement désactive le mode deux phases et utilise la liste fournie.

---

## Configuration

### Variables d'environnement

Les variables d'environnement ont la priorité absolue sur la config TOML et les valeurs par défaut.

| Variable | Description | Valeur par défaut |
|----------|-------------|-------------------|
| `RECONENGINE_PROFILE` | Profil de scan (`quick` ou `full`) | `full` |
| `RECONENGINE_PORTS` | Liste de ports nmap | liste des 72+ ports prioritaires |
| `RECONENGINE_OUTPUT_DIR` | Répertoire de sortie des rapports | `rapports` |
| `RECONENGINE_CONFIG` | Chemin vers un fichier TOML | — |
| `NMAP_PATH` | Chemin vers l'exécutable nmap | auto-détecté |

### Fichier TOML (optionnel)

```toml
# /etc/reconengine.toml
output_dir = "rapports"

[scan]
profile           = "full"
ports             = "22,80,443,8080"
discovery_timeout = 5
max_workers       = 8
```

---

## Modules

### `config.py` — Configuration centralisée

- `DEFAULT_PORTS` : 72+ ports couvrant services exposés, bases de données, accès distants, IoT/industriel
- `SCAN_PROFILES` : profils `quick` et `full` avec arguments nmap préconfigurés
- `Config.load()` : charge TOML puis surcharges env vars

### `discover.py` — Découverte d'hôtes

Point d'entrée : `discover(iface, network, timeout) → list[dict]`

Stratégie de découverte :

```
root disponible ?
  ├── oui + réseau ≤ /24 → ARP + nmap ping en parallèle (meilleure couverture)
  ├── oui + réseau > /24 → ARP seul (nmap trop lent sans contrainte)
  └── non              → nmap ping seul (limité aux réseaux ≤ /24)
```

- ARP via Scapy (`arping`) avec `inter=0` (rafale de paquets)
- nmap ping : `-PE -PP -PS22,80,443,8080 -PA80,443` (multi-sonde ICMP + TCP)
- Interfaces multiples scannées simultanément (`ThreadPoolExecutor`, max 4)
- Déduplique les IPs et exclut les IPs locales de la machine

### `scan.py` — Scan de ports

Deux fonctions principales :

**`scan_host(ip, ports, profile)`** — profil `quick` ou ports explicites

Scanne une liste de ports fixe avec les arguments du profil.

**`scan_host_twophase(ip, profile, save_dir)`** — profil `full` (défaut)

```
Phase 1 : nmap -sS -T4 --min-rate 5000 -p- -Pn --max-retries 1 --open -n
           → détecte tous les ports TCP ouverts sur 65 535 ports
Phase 2 : nmap -sS -sV -O --script vuln,default -T4 -Pn
           → service, OS, CVE uniquement sur les ports confirmés ouverts
```

Avantages du mode deux phases :
- Trouve les services sur des ports non standard (ex: SSH sur 2222, HTTP sur 8888)
- La détection de service ne s'exécute que sur les ports ouverts → gain de temps significatif
- Le paramètre `save_dir` sauvegarde les résultats au format `-oA` pour traçabilité

### `exploits.py` — Enrichissement Exploit-DB

- `find(software, max_results, cache)` : recherche via `searchsploit --json`
- Vérifie la disponibilité de `searchsploit` une seule fois au démarrage (thread-safe)
- Cache partagé entre l'affichage terminal et la génération du rapport (zéro appel dupliqué)
- Sanitise l'entrée (caractères ASCII imprimables, max 200 chars) avant le sous-processus
- Retourne `[]` si `searchsploit` absent, timeout ou erreur JSON

### `rapport.py` — Construction du rapport

Pipeline interne :

```
build_report_data() ─→ generate_report()
  ├── _build_host()          calcul vulns, sévérités, scores par hôte
  ├── _risk_from_counts()    score 0-100 et niveau textuel
  ├── _classify()            critical/high/medium/low par port/service
  ├── _build_topology()      groupement par sous-réseau /24
  ├── _generate_network_map_image()  matplotlib (thread séparé)
  ├── _build_action_plan()   top 25 actions priorisées
  └── _plain_summary()       texte explicatif non-technique
```

#### Classification de sévérité (`_classify`)

| Condition | Sévérité |
|-----------|----------|
| Exploits connus (searchsploit) | CRITIQUE |
| Port dans `CRITICAL_PORTS` ou service dans `HIGH_RISK_SERVICES` | ÉLEVÉ |
| Port < 1024 | MODÉRÉ |
| Autres ports ouverts | FAIBLE |

Un port filtré avec exploit connu est classifié CRITIQUE.

#### Scoring de risque global

Score = `Σ(poids × count) / (total × poids_critique) × 100`

| Niveau | Score | Poids unitaire |
|--------|-------|----------------|
| CRITIQUE | ≥ 75 | 30 |
| ÉLEVÉ | ≥ 50 | 18 |
| MODÉRÉ | ≥ 25 | 8 |
| FAIBLE | < 25 | 2 |

---

## Profils de scan

### `quick` — Scan rapide

```
-sS -T4 --min-rate 2000 -n --open -Pn --max-retries 1 --host-timeout 60s --min-parallelism 20
```

- SYN scan, timing agressif, résolution DNS désactivée
- Aucun script de vulnérabilité
- Timeout 60s par hôte
- Idéal pour une vue rapide des ports ouverts

### `full` — Scan complet (deux phases)

Phase 1 (découverte) :
```
-sS -T4 --min-rate 5000 -p- -Pn --max-retries 1 --open -n
```

Phase 2 (services + vulnérabilités, ports ouverts uniquement) :
```
-sS -sV -O --script vuln,default --script-args mincvss=5.0 -T4 -Pn --host-timeout 300s --max-retries 1
```

- Couvre les 65 535 ports TCP
- Détection OS (`-O`), version service (`-sV`)
- Scripts NSE `vuln` + `default`, filtre CVSSv2 ≥ 5.0
- Timeout 300s par hôte

### Ports par défaut (`DEFAULT_PORTS`)

72+ ports couvrant :

| Catégorie | Ports |
|-----------|-------|
| Accès en clair | 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 69 (TFTP), 79 (Finger) |
| Web | 80, 443, 8080, 8443, 8888, 9090 |
| Mail | 110, 143, 465, 587, 993, 995 |
| DNS / SNMP | 53, 161, 162 |
| SMB / RPC | 111, 135, 137, 139, 445 |
| Bases de données | 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017 |
| Accès distants | 2222, 3389, 5900-5902 |
| Docker | 2375, 2376, 2377 |
| IoT / Industriel | 502 (Modbus), 554 (RTSP), 1883/8883 (MQTT), 1900 (UPnP), 3702 (WS-Discovery), 5672 (AMQP) |

---

## Rapport PDF

Généré par WeasyPrint (≥ 55 requis pour `conic-gradient`) depuis le template Jinja2 `docker/tools/templates/report.html`.

### Contenu

- **Page de couverture** : identifiant de scan, date, niveau de risque global
- **Résumé exécutif** : texte non-technique, métriques clés (hôtes, vulnérabilités, taux d'exposition)
- **Cartographie réseau** : visualisation matplotlib par sous-réseau, code couleur par niveau de risque
- **Plan d'action** : jusqu'à 25 actions priorisées (critiques en premier)
- **Détail par hôte** : OS, ports, services, exploits connus, recommandations
- **Distribution de sévérité** : barres CSS avec pourcentages

### Variables Jinja2 clés

| Variable | Type | Description |
|----------|------|-------------|
| `global_risk` | str | `CRITIQUE / ELEVE / MODERE / FAIBLE` |
| `risk_score` | float | Score 0-100 |
| `hosts` | list[dict] | Données par hôte |
| `hosts[].vulnerabilities` | list[dict] | Ports avec sévérité, exploits, recommandation |
| `topology` | list[dict] | Groupes par sous-réseau /24 |
| `network_map_img` | str | Data URI PNG (matplotlib) |
| `action_plan` | list[dict] | Actions priorisées |
| `severity_pct` | dict | Pourcentages par niveau |
| `host_risk_distribution` | dict | `CRITIQUE/ELEVE/MODERE/FAIBLE` → count |
| `exposure_rate` | float | % ports ouverts ou filtrés |
| `stealth_score` | float | % ports fermés |
| `plain_summary` | str | Texte explicatif non-technique |

### Sécurité

- Le chemin de sortie PDF doit rester sous le répertoire de travail courant (protection path traversal)
- Le fichier PDF est créé avec permissions `0o600` (lecture/écriture propriétaire uniquement)

---

## Matériel

Voir [`HARDWARE.md`](HARDWARE.md) pour la liste complète des composants PCB (SoC, réseau, stockage, alimentation).

Voir [`LFS_GUIDE.md`](LFS_GUIDE.md) pour le guide Linux From Scratch ARM64 (toolchain, kernel, BLFS, déploiement systemd).
