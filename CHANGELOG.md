# Changelog

All notable changes to ReconEngine are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — 2026-04-08

### Added
- **`docker/tools/api.py`** — FastAPI HTTP server (port 8000) enabling remote scan control:
  - `POST /scans` — trigger a scan, returns `scan_id` immediately (background task)
  - `GET /scans/{id}` — poll scan status and results
  - `GET /scans` — list all scans
  - `GET /reports` — list generated PDF reports
  - `GET /reports/{filename}` — download a PDF report
  - `GET /health` — liveness probe (no auth required)
  - API key authentication via `X-API-Key` header (`RECONENGINE_API_KEY` env var)
  - Pydantic v2 input validation with pattern enforcement on `profile` field
  - Path traversal protection on report download
  - One-concurrent-scan limit (embedded hardware constraint)
- **`tests/`** — 57 unit tests covering pure functions in `cve.py`, `exploits.py`, `config.py`, `rapport.py`, and `main.py` — no network, no nmap required
- **`.github/workflows/ci.yml`** — GitHub Actions CI: test (Python 3.13) + ruff lint + Docker build
- **`pyproject.toml`** — project metadata, ruff config, pytest config, coverage settings, `[dev]` extras
- **`.env.example`** — documents every supported environment variable with defaults and descriptions
- **`PLAN.md`** — full technical audit: bugs found, weakness catalogue, prioritized action list
- **`README.md`** — replaced 1-line placeholder with full documentation (install, usage, Docker, API, config table, architecture diagram)
- **`CHANGELOG.md`** — this file

### Fixed
- **`docker/Dockerfile`** — build was broken: `requirements.txt` bind-mount failed because build context was `docker/` but the file lives at repo root. Fixed by changing compose build context to repo root (`..`) and using `COPY requirements.txt ./`
- **`docker/compose.yaml`** — rewrote from Docker boilerplate template:
  - Added `network_mode: host` (required for nmap `-sS` raw sockets and Scapy ARP)
  - Added `privileged: true` (required for `NET_RAW`/`NET_ADMIN` inside container)
  - Fixed service name from `server` → `reconengine`
  - Added all env var mappings
  - Added volume mount for PDF report persistence
  - CMD now points to `api.py` (port 8000 is now actually used)
- **`docker/tools/scan.py`** — `scan_host()` now retries with `quick` profile when `full` returns no result (host timeout on vuln scripts, strict firewall, distant VLAN host)
- **`docker/tools/main.py`** — `render_host()` no longer shows an empty table when nmap detects OS but all ports are `closed` (displayed "Aucun port ouvert ou filtré détecté." instead)
- **`docker/tools/main.py`** — Phase 3 now lists unreachable hosts (discovered via ARP but failed TCP scan) with `⊘ ip — aucune réponse au scan TCP`
- **`docker/tools/discover.py`** — ARP timeout for `/16` networks increased from 10s → 30s; added 15s tier for `/17–/20` (WiFi adds latency vs wired)
- **`docker/tools/config.py`** — added `--max-retries 3` to `full` profile (compensates for WiFi packet loss)
- **`docker/tools/templates/report.html`** — replaced both `conic-gradient` gauge implementations with inline SVG (`stroke-dasharray` circles) — eliminates all WeasyPrint warnings about unsupported CSS

### Changed
- **`docker/Dockerfile`** — base image updated from `python:3.14.2-slim` (pre-release) to `python:3.13-slim` (stable LTS)
- **`docker/Dockerfile`** — FastAPI + Uvicorn + Pydantic installed as a dedicated layer (cached separately from requirements.txt)

---

## Previous work (from git log)

| Commit | Description |
|--------|-------------|
| `f8aba1c` | test claude improve |
| `dffe3fd` | remove comment |
| `84b89fa` | 2 scan options (quick / full profiles) |
| `300a0bb` | modif minrate scan |
| `a6c3dbd` | nmap args |
| `3ab8c3f` | fix rapport gen |
| `630077b` | improve rapport rendement |
| `ad88bf2` | fix git |
| `2cae6fd` | improve rapport + gitignore maj |
| `5d8b9a6` | Merge branch 'feat/discover' into feat/rapport |
