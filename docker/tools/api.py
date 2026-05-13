"""
ReconEngine HTTP API server.

Wraps the 4-phase scan pipeline behind a FastAPI HTTP interface so that
ReconEngine can be controlled remotely — useful when deployed as a Docker
container on embedded hardware (the hardware has no screen, but you can
reach port 8000 from any device on the network).

Endpoints:
  POST /scans             — start a scan (returns scan_id immediately)
  GET  /scans/{scan_id}   — poll scan status / results
  GET  /reports           — list generated PDF reports
  GET  /reports/{name}    — download a PDF
  GET  /health            — liveness probe (no auth)

Authentication: X-API-Key header (value from RECONENGINE_API_KEY env var).

Run:
  sudo python tools/api.py                 # default: 0.0.0.0:8000
  sudo uvicorn tools.api:app --host 0.0.0.0 --port 8000
"""
import contextlib
import datetime
import hmac
import logging
import os
import pathlib
import sqlite3
import sys
import threading
import time
import uuid
from enum import StrEnum
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

# ── Path setup (tools/ may not be on sys.path when invoked as api.py) ─────────
_THIS_DIR = pathlib.Path(__file__).parent.resolve()
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import config as cfg_mod  # noqa: E402
import discover  # noqa: E402
import rapport  # noqa: E402
import scan  # noqa: E402

cfg_mod.setup_logging()
log = logging.getLogger(__name__)

# ── Auth ───────────────────────────────────────────────────────────────────────
_API_KEY = os.environ.get("RECONENGINE_API_KEY", "changeme")
if _API_KEY == "changeme":
    log.warning(
        "RECONENGINE_API_KEY is set to the default 'changeme'. "
        "Set a strong key before exposing this API on a public interface."
    )

# Brute-force protection : compteur d'échecs par IP sur une fenêtre glissante.
_auth_failures: dict[str, list[float]] = {}
_auth_lock = threading.Lock()
_MAX_AUTH_FAILURES = 10   # tentatives autorisées par fenêtre
_AUTH_WINDOW = 60.0       # fenêtre en secondes


def _require_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()

    with _auth_lock:
        # Nettoyer les entrées expirées + vérifier le rate limit
        recent = [t for t in _auth_failures.get(client_ip, []) if now - t < _AUTH_WINDOW]
        _auth_failures[client_ip] = recent
        if len(recent) >= _MAX_AUTH_FAILURES:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed authentication attempts. Try again later.",
            )

    # Comparaison en temps constant pour prévenir les timing attacks
    key_provided = x_api_key or ""
    if not hmac.compare_digest(key_provided, _API_KEY):
        with _auth_lock:
            _auth_failures.setdefault(client_ip, []).append(now)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


AuthDep = Annotated[None, Depends(_require_api_key)]

# ── Application ────────────────────────────────────────────────────────────────

@contextlib.asynccontextmanager
async def _lifespan(application: FastAPI):  # noqa: ARG001
    """Initialize DB on startup; mark orphaned running scans as error."""
    _db_init()
    with _db_connect() as conn:
        orphans = conn.execute(
            "SELECT scan_id FROM scans WHERE status = ?", (ScanStatus.RUNNING,)
        ).fetchall()
    for row in orphans:
        _db_update(
            row["scan_id"],
            status=ScanStatus.ERROR,
            finished_at=datetime.datetime.now().isoformat(),
            error="Process restarted while scan was running",
        )
        log.warning("Marked orphaned scan %s as error", row["scan_id"])
    yield  # application runs here


app = FastAPI(
    title="ReconEngine API",
    description="Remote control for the ReconEngine network audit pipeline.",
    version="0.1.0",
    contact={"name": "ReconEngine"},
    lifespan=_lifespan,
)


class ScanStatus(StrEnum):
    PENDING   = "pending"
    RUNNING   = "running"
    DONE      = "done"
    ERROR     = "error"


# ── SQLite-backed scan registry ────────────────────────────────────────────────
# Persists across container restarts. Stored alongside the PDF reports so the
# same volume mount covers both.
_DB_PATH = pathlib.Path(os.environ.get("RECONENGINE_OUTPUT_DIR", "rapports")) / "scans.db"
_db_lock = threading.Lock()  # sqlite3 in WAL mode is thread-safe but we serialize writes


def _db_connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _db_init() -> None:
    with _db_lock, _db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id      TEXT PRIMARY KEY,
                status       TEXT NOT NULL,
                profile      TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                duration     TEXT,
                hosts_found  INTEGER DEFAULT 0,
                hosts_scanned INTEGER DEFAULT 0,
                report_file  TEXT,
                error        TEXT
            )
        """)
        conn.commit()


def _db_insert(entry: dict[str, Any]) -> None:
    with _db_lock, _db_connect() as conn:
        conn.execute(
            """INSERT INTO scans
               (scan_id, status, profile, started_at, finished_at, duration,
                hosts_found, hosts_scanned, report_file, error)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                entry["scan_id"], entry["status"], entry["profile"],
                entry["started_at"], entry.get("finished_at"), entry.get("duration"),
                entry.get("hosts_found", 0), entry.get("hosts_scanned", 0),
                entry.get("report_file"), entry.get("error"),
            ),
        )
        conn.commit()


def _db_update(scan_id: str, **kwargs: Any) -> None:
    if not kwargs:
        return
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [scan_id]
    with _db_lock, _db_connect() as conn:
        conn.execute(f"UPDATE scans SET {cols} WHERE scan_id = ?", vals)  # noqa: S608
        conn.commit()


def _db_get(scan_id: str) -> dict[str, Any] | None:
    with _db_connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def _db_list() -> list[dict[str, Any]]:
    with _db_connect() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
    return [dict(r) for r in rows]


# ── In-memory "running" state (DB stores persistent state) ────────────────────
# We keep an in-memory dict only to track the "running" status in real-time,
# since the DB update for hosts_scanned would otherwise hammer disk.
_running: dict[str, dict[str, Any]] = {}
_running_lock = threading.Lock()


# ── Pydantic models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    profile: str = Field(
        default="full",
        description=(
            "Scan profile. Available: "
            + ", ".join(f"'{k}'" for k in cfg_mod.SCAN_PROFILES)
            + ". See GET /profiles for details."
        ),
    )
    target: str | None = Field(
        default=None,
        description="Target CIDR (e.g. 192.168.1.0/24). Omit to auto-detect from interface.",
        examples=["192.168.1.0/24"],
    )
    iface: str | None = Field(
        default=None,
        description="Network interface (e.g. eth0, wlan0). Omit to auto-detect.",
    )
    ports: str | None = Field(
        default=None,
        description="Nmap port expression (e.g. '22,80,443' or '1-1024'). Omit for default set.",
    )
    no_pdf: bool = Field(
        default=False,
        description="Skip PDF generation (faster, terminal results only).",
    )

    @field_validator("profile")
    @classmethod
    def _check_profile(cls, v: str) -> str:
        valid = set(cfg_mod.SCAN_PROFILES.keys())
        if v not in valid:
            raise ValueError(
                f"Profil inconnu : '{v}'. Valeurs valides : {', '.join(sorted(valid))}."
            )
        return v


class ProfileInfo(BaseModel):
    name:        str
    description: str
    arguments:   str
    ports:       str | None = None


class ScanSummary(BaseModel):
    scan_id:      str
    status:       ScanStatus
    profile:      str
    started_at:   str
    finished_at:  str | None = None
    duration:     str | None = None
    hosts_found:  int = 0
    hosts_scanned: int = 0
    report_file:  str | None = None
    error:        str | None = None


class ReportEntry(BaseModel):
    filename: str
    size_kb:  float
    created:  str


# ── Background scan task ───────────────────────────────────────────────────────

def _run_scan(scan_id: str, req: ScanRequest) -> None:
    """Executes the full ReconEngine pipeline in a background thread."""

    def _live(**kwargs: Any) -> None:
        """Update live (in-memory) state visible during the scan."""
        with _running_lock:
            if scan_id in _running:
                _running[scan_id].update(kwargs)

    def _persist(**kwargs: Any) -> None:
        """Persist state to SQLite (called at milestones and completion)."""
        _db_update(scan_id, **kwargs)
        _live(**kwargs)

    _persist(status=ScanStatus.RUNNING)
    log.info("[%s] Scan started (profile=%s)", scan_id, req.profile)

    try:
        cfg = cfg_mod.Config.load()
        cfg.scan.profile = req.profile
        if req.ports:
            cfg.scan.ports = req.ports
        elif profile_ports := cfg_mod.SCAN_PROFILES[req.profile].get("ports"):
            # Use the profile's built-in port list if the caller didn't specify one
            cfg.scan.ports = profile_ports

        # ── Phase 1: Discovery ─────────────────────────────────────────────────
        discovered = discover.discover(
            iface=req.iface or os.environ.get("RECONENGINE_IFACE") or None,
            network=req.target,
            timeout=cfg.scan.discovery_timeout,
        )
        ips = [h["ip"] for h in discovered]
        _persist(hosts_found=len(ips))
        log.info("[%s] Discovered %d host(s)", scan_id, len(ips))

        if not ips:
            _persist(
                status=ScanStatus.DONE,
                finished_at=datetime.datetime.now().isoformat(),
                duration="0s",
            )
            with _running_lock:
                _running.pop(scan_id, None)
            return

        # ── Phase 2: Parallel scan ─────────────────────────────────────────────
        from concurrent.futures import ThreadPoolExecutor, as_completed

        exploit_cache: dict = {}
        scan_results: dict = {}
        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=cfg.scan.max_workers) as executor:
            futures = {
                executor.submit(scan.scan_host, ip, cfg.scan.ports, cfg.scan.profile): ip
                for ip in ips
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    log.error("[%s] Scan failed for %s: %s", scan_id, ip, exc)
                    result = None
                if result is not None:
                    scan_results[ip] = result
                # Live update only (not every result to DB — too noisy on disk)
                _live(hosts_scanned=len(scan_results))

        elapsed = time.monotonic() - t0
        m, s = divmod(int(elapsed), 60)
        duration = f"{m}m{s:02d}s"

        # ── Phase 3 (optional): PDF report ────────────────────────────────────
        report_file = None
        if scan_results and not req.no_pdf:
            import main as main_mod
            n_ports = main_mod._port_count(cfg.scan.ports)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{cfg.output_dir}/Rapport_Audit_{ts}.pdf"
            try:
                out = rapport.generate_report(
                    scan_results,
                    output_path=output_path,
                    duration=duration,
                    total_ports=n_ports,
                    cache=exploit_cache,
                    discovered_ips=discovered,
                )
                report_file = pathlib.Path(out).name
                log.info("[%s] Report: %s", scan_id, out)
            except Exception as exc:
                log.error("[%s] PDF generation failed: %s", scan_id, exc)

        _persist(
            status=ScanStatus.DONE,
            finished_at=datetime.datetime.now().isoformat(),
            duration=duration,
            hosts_scanned=len(scan_results),
            report_file=report_file,
        )
        log.info("[%s] Done in %s — %d host(s) scanned", scan_id, duration, len(scan_results))

    except Exception as exc:
        log.exception("[%s] Scan error: %s", scan_id, exc)
        _persist(
            status=ScanStatus.ERROR,
            finished_at=datetime.datetime.now().isoformat(),
            error=str(exc),
        )

    finally:
        with _running_lock:
            _running.pop(scan_id, None)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"], summary="Liveness probe — no auth required")
def health() -> dict:
    with _running_lock:
        running_count = len(_running)
    return {"status": "ok", "scans_running": running_count}


@app.get(
    "/profiles",
    tags=["system"],
    summary="List available scan profiles — no auth required",
    response_model=list[ProfileInfo],
)
def list_profiles() -> list[ProfileInfo]:
    """Returns all built-in scan profiles with their nmap arguments and optional port overrides."""
    return [
        ProfileInfo(
            name=name,
            description=p["description"],
            arguments=p["arguments"],
            ports=p.get("ports"),
        )
        for name, p in cfg_mod.SCAN_PROFILES.items()
    ]


@app.post(
    "/scans",
    tags=["scans"],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new scan",
    response_model=ScanSummary,
)
def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    _auth: AuthDep,
) -> ScanSummary:
    """
    Enqueue a new scan. Returns immediately with a `scan_id` you can poll at
    `GET /scans/{scan_id}`.

    Only one scan can run at a time (embedded hardware constraint).
    """
    with _running_lock:
        if _running:
            running_id = next(iter(_running))
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A scan is already running (id={running_id}). Wait for it to finish.",
            )

    scan_id = str(uuid.uuid4())[:8]
    now = datetime.datetime.now().isoformat()
    entry: dict[str, Any] = {
        "scan_id":       scan_id,
        "status":        ScanStatus.PENDING,
        "profile":       req.profile,
        "started_at":    now,
        "finished_at":   None,
        "duration":      None,
        "hosts_found":   0,
        "hosts_scanned": 0,
        "report_file":   None,
        "error":         None,
    }
    _db_insert(entry)
    with _running_lock:
        _running[scan_id] = dict(entry)

    background_tasks.add_task(_run_scan, scan_id, req)
    return ScanSummary(**entry)


@app.get(
    "/scans/{scan_id}",
    tags=["scans"],
    summary="Get scan status and results",
    response_model=ScanSummary,
)
def get_scan(_auth: AuthDep, scan_id: str) -> ScanSummary:
    # Prefer live in-memory state for running scans (has up-to-date hosts_scanned)
    with _running_lock:
        live = _running.get(scan_id)
    if live:
        return ScanSummary(**live)
    entry = _db_get(scan_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanSummary(**entry)


@app.get(
    "/scans",
    tags=["scans"],
    summary="List all scans (most recent first)",
    response_model=list[ScanSummary],
)
def list_scans(_auth: AuthDep) -> list[ScanSummary]:
    entries = _db_list()
    # Overlay live state for any running scans
    with _running_lock:
        live_copy = dict(_running)
    merged = []
    for e in entries:
        sid = e["scan_id"]
        merged.append(ScanSummary(**(live_copy.get(sid, e))))
    return merged


@app.get(
    "/reports",
    tags=["reports"],
    summary="List available PDF reports",
    response_model=list[ReportEntry],
)
def list_reports(_auth: AuthDep) -> list[ReportEntry]:
    cfg = cfg_mod.Config.load()
    report_dir = pathlib.Path(cfg.output_dir)
    if not report_dir.exists():
        return []
    pdfs = sorted(report_dir.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [
        ReportEntry(
            filename=p.name,
            size_kb=round(p.stat().st_size / 1024, 1),
            created=datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
        )
        for p in pdfs
    ]


@app.get(
    "/reports/{filename}",
    tags=["reports"],
    summary="Download a PDF report",
    response_class=FileResponse,
)
def download_report(_auth: AuthDep, filename: str) -> FileResponse:
    # Première passe : rejeter les caractères manifestement dangereux
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    cfg = cfg_mod.Config.load()
    output_dir = pathlib.Path(cfg.output_dir).resolve()
    path = (output_dir / filename).resolve()
    # Vérification canonique : le chemin résolu doit rester sous output_dir
    if not str(path).startswith(str(output_dir) + os.sep) and path != output_dir:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not path.exists() or path.suffix != ".pdf":
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type="application/pdf", filename=filename)


# ── Entry point ────────────────────────────────────────────────────────────────

def run() -> None:
    """Start the Uvicorn server. Called by the `reconengine-api` script entry point."""
    import uvicorn
    host = os.environ.get("RECONENGINE_API_HOST", "0.0.0.0")
    port = int(os.environ.get("RECONENGINE_API_PORT", "8000"))
    log.info("Starting ReconEngine API on %s:%d", host, port)
    uvicorn.run("api:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    run()
