# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ReconEngine is a network reconnaissance and vulnerability auditing tool designed to run on custom embedded hardware (PCB). It discovers live hosts, scans ports/services in parallel, correlates Exploit-DB entries, and generates French-language PDF audit reports.

## Running the Tool

```bash
# Via Docker Compose
cd docker && docker compose up --build

# Direct execution (requires root for ARP + nmap raw sockets)
cd docker/tools
python main.py                        # profil par défaut (full)
python main.py quick                  # scan rapide, sans scripts vuln
python main.py full -t 192.168.1.0/24 # réseau ciblé
python main.py -i eth0 --ports 22,80,443,8080 -o /tmp/audit.pdf

# Variables d'environnement
RECONENGINE_PROFILE=quick|full
RECONENGINE_PORTS=22,80,443          # format nmap
RECONENGINE_OUTPUT_DIR=rapports
RECONENGINE_CONFIG=/etc/reconengine.toml   # fichier TOML optionnel
NMAP_PATH=/usr/bin/nmap
```

**Aucun test automatisé configuré.** Les modules peuvent être exécutés directement :
```bash
python discover.py -n 192.168.1.0/24   # test découverte
python rapport.py                       # rapport test sur 127.0.0.1
```

## Architecture : Pipeline en 4 phases

```
discover.py  ──→  scan.py (ThreadPoolExecutor)  ──→  rapport.py  ──→  PDF
                      ↕ cache partagé
                  exploits.py (searchsploit)
                  cve.py      (scripts nmap + NVD API)
```

### Modules

**`config.py`** — Configuration centralisée
- `DEFAULT_PORTS` : liste de ~65 ports de sécurité prioritaires (plus ciblée que 1-3389)
- `SCAN_PROFILES` : `quick` (`-sS -T4 --min-rate 2000`) et `full` (`-sS -sV -O --script vuln`)
- `Config.load()` : charge TOML + surcharges env vars (env vars prioritaires)

**`discover.py`** — Découverte d'hôtes
- ARP broadcast via Scapy (prioritaire, nécessite root)
- Fallback nmap ping sweep (`-sn`) sur réseaux ≤ /24
- Accès netmask via `fcntl SIOCGIFNETMASK` (Linux only)
- Point d'entrée public : `discover(iface, network, timeout) → list[str]`

**`scan.py`** — Scan de ports
- Wraps `python-nmap` ; résout nmap via `NMAP_PATH` > `shutil.which` > bundled
- `scan_host(ip, ports, profile)` → `nmap.PortScannerHostDict | None`
- `get_os(data)` → extrait le meilleur match OS (nécessite flag `-O` dans le profil)
- `_get_portscanner()` aussi utilisé par `discover.py`

**`cve.py`** — Enrichissement CVE/CVSS
- `parse_nmap_scripts(script_data)` : extrait CVE IDs + scores CVSS depuis `pinfo['script']` (format vulners, vuln, Risk factor générique)
- `query_nvd(product, version, cache)` : API NVD v2 par product+version, 2 passes (précise puis générale), throttle intégré
- `get_cve_data(product, version, script_data, cache)` → dict avec `max_cvss`, `cve_list`, `severity_class`, `source`
- `NVD_API_KEY` env var : active le mode clé API (50 req/30s vs 5 sans clé)
- Fallback gracieux si hors ligne : utilise uniquement les scripts nmap

**`exploits.py`** — Enrichissement exploit
- Vérifie la disponibilité de `searchsploit` une seule fois au démarrage
- `find(software, max_results, cache)` : lookup avec cache externe partageable
- Timeout 10s par requête ; retourne `[]` si searchsploit absent ou timeout

**`rapport.py`** — Construction du rapport et PDF
- `_classify(port, pinfo, exploits, cve_data)` → severity : CVSS réel > exploit sans score > CRITICAL_PORTS/HIGH_RISK_SERVICES > port < 1024
- `RECOMMENDATIONS` : texte d'action par niveau (critical/high/medium/low)
- `build_report_data(scan_results, total_ports, cache)` → dict contexte Jinja2
- `generate_report(...)` : crée le dossier de sortie, rend le template, produit le PDF

**`main.py`** — Orchestration
- 4 phases affichées : Découverte → Scan → Résultats terminal → PDF
- `ThreadPoolExecutor(max_workers=cfg.scan.max_workers)` pour scanner plusieurs hôtes simultanément
- `exploit_cache: dict` partagé entre `render_host()` et `rapport.generate_report()` pour éviter les appels searchsploit dupliqués
- Rich `Progress` avec barre pendant le scan

### Template PDF
- `docker/tools/templates/report.html` (Jinja2 + WeasyPrint)
- Jauge de risque via `conic-gradient` CSS (WeasyPrint ≥ 55 requis)
- Graphique de répartition : barres CSS (`severity_pct.*`)
- Clés Jinja2 critiques : `global_risk`, `severity_pct`, `host_risk_distribution` (clés `CRITIQUE/ELEVE/MODERE/FAIBLE`), `hosts[].os`, `hosts[].vulnerabilities[].exploits`, `hosts[].vulnerabilities[].recommendation`

## Matériel et LFS

- `HARDWARE.md` : liste des composants PCB (SoC, réseau, stockage, alimentation, modules optionnels)
- `LFS_GUIDE.md` : guide complet Linux From Scratch ARM64 (toolchain, kernel, BLFS, déploiement systemd)
