# ReconEngine

Network reconnaissance and vulnerability auditing tool designed for custom embedded hardware (ARM64 PCB). Discovers live hosts, scans ports and services in parallel, correlates CVE data and Exploit-DB entries, and produces French-language PDF audit reports.

## Features

- **Host discovery** — ARP broadcast (Scapy) + nmap ping sweep, auto-detects network interface
- **Parallel scanning** — ThreadPoolExecutor, configurable workers, full nmap feature set
- **CVE enrichment** — nmap vuln/vulners scripts + NVD API v2 (NIST), offline-capable
- **Exploit correlation** — searchsploit (Exploit-DB) with normalized queries and shared cache
- **PDF report** — Jinja2 + WeasyPrint, French language, risk gauges, action plan, network topology map
- **HTTP API** — FastAPI server (port 8000) for remote scan triggering and report download
- **Two scan profiles** — `quick` (ports only, ~30s) and `full` (services + OS + vuln scripts)

## Quick start

### Direct execution (requires root + nmap)

```bash
cd docker
python -m venv .venv && source .venv/bin/activate
pip install -r ../requirements.txt
pip install "fastapi>=0.111" "uvicorn[standard]>=0.30" "pydantic>=2.7"

# CLI scan
sudo python tools/main.py                         # full profile, auto-detect network
sudo python tools/main.py quick                   # fast scan, no vuln scripts
sudo python tools/main.py full -t 192.168.1.0/24  # targeted CIDR
sudo python tools/main.py -i wlan0 --ports 22,80,443,8080

# HTTP API server (port 8000)
sudo python tools/api.py
```

### Docker (recommended)

```bash
# Build and start the API server
cd docker
docker compose up --build

# Trigger a scan via HTTP
curl -X POST http://localhost:8000/scans \
  -H "X-API-Key: changeme" \
  -H "Content-Type: application/json" \
  -d '{"profile": "full", "iface": "eth0"}'

# Poll status
curl http://localhost:8000/scans/{scan_id} -H "X-API-Key: changeme"

# Download report
curl http://localhost:8000/reports/Rapport_Audit_20260408.pdf \
  -H "X-API-Key: changeme" -o report.pdf
```

## Configuration

All settings can be overridden by environment variables (highest priority) or a TOML config file.

| Variable | Default | Description |
|----------|---------|-------------|
| `RECONENGINE_PROFILE` | `full` | Scan profile: `quick` or `full` |
| `RECONENGINE_PORTS` | built-in set | Nmap port expression (`22,80,443` or `1-1024`) |
| `RECONENGINE_OUTPUT_DIR` | `rapports` | Directory for generated PDF reports |
| `RECONENGINE_MAX_WORKERS` | `8` | Parallel scan threads |
| `RECONENGINE_DISCOVERY_TIMEOUT` | `5` | ARP discovery timeout (seconds) |
| `RECONENGINE_IFACE` | auto | Network interface (`eth0`, `wlan0`, …) |
| `RECONENGINE_API_KEY` | `changeme` | API key for HTTP server (**change in production!**) |
| `RECONENGINE_CONFIG` | — | Path to TOML config file |
| `NVD_API_KEY` | — | NVD API key — 50 req/30s vs 5 req/30s without |
| `NMAP_PATH` | auto | Override nmap binary path |

Copy `.env.example` to `.env` and edit before running Docker.

### TOML config file

```toml
[scan]
profile           = "full"
ports             = "22,80,443,8080"
max_workers       = 4
discovery_timeout = 10

output_dir = "/data/rapports"
```

## Scan profiles

| Profile | Use case | Approx. time |
|---------|----------|-------------|
| `quick` | Fast port enumeration only | 30–60 s |
| `full`  | Deep audit: services + OS + CVE scripts | 2–10 min / host |

## HTTP API

All endpoints except `/health` require the `X-API-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scans` | Start a scan — returns `scan_id` |
| `GET`  | `/scans/{id}` | Poll status and summary |
| `GET`  | `/reports` | List available PDF reports |
| `GET`  | `/reports/{filename}` | Download a PDF |
| `GET`  | `/health` | Liveness probe |

Interactive docs: `http://localhost:8000/docs`

## Development

```bash
# Install with dev extras
pip install -e ".[dev]"

# Run tests (no network/nmap required)
pytest tests/ -v

# Lint
ruff check docker/tools/ tests/
```

## Architecture

```
discover.py  ──→  scan.py (ThreadPoolExecutor)  ──→  rapport.py  ──→  PDF
                      ↕ shared exploit/CVE cache
                  exploits.py (searchsploit / Exploit-DB)
                  cve.py      (nmap scripts + NVD API v2)

api.py  ──→  background scan pipeline  ──→  GET /reports/{pdf}
```

## Hardware target

**Orange Pi Zero 3** — Allwinner H618, 4× Cortex-A53 @ 1.5 GHz, 2 GB LPDDR4, ~€35

See [HARDWARE.md](HARDWARE.md) for the full PCB BOM and [LFS_GUIDE.md](LFS_GUIDE.md) for the ARM64 Linux From Scratch deployment guide.

## Requirements

- Linux (ARP discovery uses Linux-only `fcntl` ioctl)
- Python 3.13+
- `nmap` system package
- `searchsploit` optional (from `exploitdb` package — enriches exploit data)
- Root privileges (nmap `-sS` raw sockets + Scapy ARP broadcast)
