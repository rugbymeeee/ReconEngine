# ReconEngine

ReconEngine est un outil de reconnaissance réseau et d'audit de sécurité conçu pour un environnement ARM64 embarqué. Il découvre les hôtes actifs, scanne les ports en parallèle, enrichit les résultats avec les données CVE et Exploit-DB, puis génère un rapport PDF en français.

## Fonctionnalités

- Découverte d'hôtes via ARP broadcast, avec fallback nmap ping sweep
- Scan TCP parallèle avec profils `quick` et `full`
- Enrichissement CVE/CVSS via scripts nmap et API NVD
- Corrélation Exploit-DB via `searchsploit`
- Génération de rapport PDF avec Jinja2 et WeasyPrint
- API HTTP FastAPI pour déclencher et suivre les scans à distance
- Indicateur d'état matériel optionnel via `status.py`

## Architecture

```text
discover.py  ->  scan.py  ->  rapport.py  ->  PDF
                    |            |
                    |            +-> cve.py / exploits.py
                    +-> main.py / api.py
```

## Démarrage rapide

### Exécution directe

```bash
cd docker/tools
python main.py            # profil full par défaut
python main.py quick      # scan rapide
python main.py full -t 192.168.1.0/24
python api.py             # API HTTP sur le port 8000
```

### Docker

```bash
cd docker
docker compose up --build
```

## Configuration

Les variables d'environnement sont prioritaires sur le fichier TOML.

- `RECONENGINE_PROFILE` : `quick` ou `full`
- `RECONENGINE_PORTS` : expression nmap (`22,80,443` ou `1-1024`)
- `RECONENGINE_OUTPUT_DIR` : répertoire des rapports PDF
- `RECONENGINE_MAX_WORKERS` : nombre de threads de scan
- `RECONENGINE_DISCOVERY_TIMEOUT` : délai de découverte ARP
- `RECONENGINE_IFACE` : interface réseau à utiliser
- `RECONENGINE_API_KEY` : clé d'authentification de l'API HTTP
- `NVD_API_KEY` : clé NVD optionnelle
- `NMAP_PATH` : chemin personnalisé vers nmap

## Profils de scan

- `quick` : scan port-only rapide
- `full` : scan complet avec détection de version, OS et scripts de vulnérabilité

## Modules principaux

- `discover.py` : découverte réseau
- `scan.py` : scan de ports et de services
- `cve.py` : enrichissement CVE/CVSS
- `exploits.py` : enrichissement Exploit-DB
- `rapport.py` : agrégation des résultats et génération PDF
- `main.py` : orchestration CLI
- `api.py` : API FastAPI
- `status.py` : LED de statut du PCB, optionnel

## Matériel

Voir [HARDWARE.md](HARDWARE.md) pour la BOM complète du PCB et [LFS_GUIDE.md](LFS_GUIDE.md) pour le déploiement Linux From Scratch ARM64.

## Développement

```bash
pytest tests/ -v
ruff check docker/tools/ tests/
```