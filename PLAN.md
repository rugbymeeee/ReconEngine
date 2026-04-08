# ReconEngine — Technical Audit & Improvement Plan

*Generated: 2026-04-08 — autonomous senior engineer pass*

---

## What the project does

ReconEngine is a **network reconnaissance and vulnerability auditing tool** designed to run on custom embedded hardware (Orange Pi Zero 3, ARM64). It:

1. Discovers live hosts via ARP broadcast (Scapy) + nmap ping sweep
2. Scans ports/services in parallel (ThreadPoolExecutor)
3. Enriches results with CVE data (nmap scripts + NVD API v2) and exploit references (searchsploit)
4. Generates a French-language PDF audit report (Jinja2 + WeasyPrint)

**Target hardware:** Orange Pi Zero 3 (Allwinner H618, 4× Cortex-A53, 2 GB RAM, ~€75 PCB)
**Primary interface:** CLI (`python main.py [quick|full]`) or HTTP API (port 8000 in Docker)

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.13+ |
| Scanning | nmap + python-nmap, Scapy (ARP) |
| CVE intel | NVD API v2 (NIST), nmap vuln scripts |
| Exploit intel | searchsploit (Exploit-DB) |
| PDF output | Jinja2 + WeasyPrint |
| Terminal UI | Rich |
| Network viz | matplotlib |
| HTTP API | FastAPI (new) |
| Validation | Pydantic (new) |
| Tests | pytest (new) |
| Containers | Docker + Compose |

---

## Findings — Bugs & Weaknesses

### 🔴 Critical bugs

| # | File | Issue |
|---|------|-------|
| 1 | `docker/Dockerfile` | `requirements.txt` bind-mount uses `source=requirements.txt` but build context is `docker/` — the file lives at repo root → **Docker build fails** |
| 2 | `docker/compose.yaml` | No `network_mode: host` → nmap raw sockets (`-sS`) and Scapy ARP won't work inside container |
| 3 | `docker/compose.yaml` | No `privileged: true` or `cap_add: [NET_ADMIN, NET_RAW]` → root-requiring operations (ARP, nmap -sS) silently fail |
| 4 | `docker/compose.yaml` | Port 8000 exposed but nothing listens on it → container exits immediately |

### 🟠 High-priority issues

| # | File | Issue |
|---|------|-------|
| 5 | `cve.py:154` | `f"nmap"` is a no-op f-string (no interpolation) → use `"nmap"` |
| 6 | `cve.py` | `_nvd_available` global mutated from multiple threads (Phase 2 scan is parallel) — not thread-safe |
| 7 | `cve.py` | `_last_nvd_call` shared global across threads → NVD throttle can break under concurrent scan |
| 8 | Whole repo | No tests at all — zero coverage |
| 9 | `README.md` | Single line `# ReconEngine` — useless for contributors or operators |
| 10 | `requirements.txt` | No dev/test deps (pytest, httpx, etc.); no pyproject.toml |

### 🟡 Medium-priority issues

| # | File | Issue |
|---|------|-------|
| 11 | `discover.py` | `_get_netmask()` is Linux-only (fcntl/ioctl SIOCGIFNETMASK) — silently returns None on macOS/BSD |
| 12 | `rapport.py` | `_generate_network_map_image()` imports matplotlib inside the function — import error swallowed silently |
| 13 | `config.py` | `_NVD_MIN_INTERVAL` computed at import time — if `NVD_API_KEY` env var is set after `import cve`, rate limit won't update |
| 14 | All | Missing `.env.example` — operators don't know which env vars exist |
| 15 | All | No structured logging — hard to debug issues in Docker/systemd |
| 16 | `scan.py` | No timeout on the overall port scan per host beyond `--host-timeout` nmap flag |

### 🟢 Low-priority / polish

| # | File | Issue |
|---|------|-------|
| 17 | `main.py` | MAC address not displayed in Phase 3 terminal for discovered hosts |
| 18 | All | Inconsistent `Optional[bool]` usage (mix of `bool | None` and `Optional`) |
| 19 | `cve.py` | `query_nvd()` 2-pass logic adds a second NVD call even when product is generic |
| 20 | All | No `CHANGELOG.md` |
| 21 | All | No CI config (`.github/workflows/`) |
| 22 | `compose.yaml` | Default Docker template boilerplate comments still present |

---

## Prioritized Action List

### Phase 1 — Foundation (this pass)

- [x] Fix Dockerfile: move `requirements.txt` into build context (change compose `context` to repo root)
- [x] Fix compose.yaml: add `network_mode: host`, `privileged: true`, proper CMD
- [x] Write `README.md` with install, usage, config, Docker, hardware sections
- [x] Add `pyproject.toml` with dev/test extras
- [x] Add `.env.example` documenting all supported env vars
- [x] Fix `cve.py` f-string bug + thread-safety issues

### Phase 2 — Quality (this pass)

- [x] Add `tests/` with pytest coverage for pure functions (no network needed)
- [x] Add `.github/workflows/ci.yml` (lint + test on push/PR)
- [x] Write `CHANGELOG.md`

### Phase 3 — Features (this pass)

- [x] Add `docker/tools/api.py` — FastAPI HTTP server that:
  - `POST /scans` — trigger a scan (async background task)
  - `GET /scans/{id}` — poll scan status + results
  - `GET /reports` — list PDF reports
  - `GET /reports/{filename}` — download PDF
  - `GET /health` — liveness probe
  - API key authentication (header `X-API-Key`)
- [x] Update Dockerfile CMD to run `api.py` in Docker mode (port 8000 actually used)
- [x] Add Pydantic models for all API inputs/outputs

### Phase 4 — Future work (not in this pass)

- [ ] Async scan execution (asyncio + asyncio.subprocess instead of ThreadPoolExecutor)
- [ ] Persistent job storage (SQLite) for multi-scan history
- [ ] OLED display integration (SSD1306 via I²C) — progress and result summary
- [ ] WS2812B LED status indicators (scanning=blue pulse, done=green/red by risk)
- [ ] macOS/BSD compat for `_get_netmask()` (use `netifaces` or `psutil`)
- [ ] IPv6 support
- [ ] Custom nmap NSE script bundling
- [ ] Slack/Teams webhook for alert delivery
