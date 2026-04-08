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
import datetime
import logging
import os
import pathlib
import sys
import threading
import time
import uuid
from enum import Enum
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# ── Path setup (tools/ may not be on sys.path when invoked as api.py) ─────────
_THIS_DIR = pathlib.Path(__file__).parent.resolve()
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import config as cfg_mod
import discover
import rapport
import scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Auth ───────────────────────────────────────────────────────────────────────
_API_KEY = os.environ.get("RECONENGINE_API_KEY", "changeme")
if _API_KEY == "changeme":
    log.warning(
        "RECONENGINE_API_KEY is set to the default 'changeme'. "
        "Set a strong key before exposing this API on a public interface."
    )


def _require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    if x_api_key != _API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


AuthDep = Annotated[None, Depends(_require_api_key)]

# ── Application ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ReconEngine API",
    description="Remote control for the ReconEngine network audit pipeline.",
    version="0.1.0",
    contact={"name": "ReconEngine"},
)

# ── In-memory scan registry (sufficient for single-device embedded use) ────────
class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    DONE      = "done"
    ERROR     = "error"


_scans: dict[str, dict[str, Any]] = {}
_scans_lock = threading.Lock()


# ── Pydantic models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    profile: str = Field(
        default="full",
        pattern="^(quick|full)$",
        description="Scan profile: 'quick' (ports only) or 'full' (services + OS + CVE scripts)",
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
    import exploits

    def _update(**kwargs: Any) -> None:
        with _scans_lock:
            _scans[scan_id].update(kwargs)

    _update(status=ScanStatus.RUNNING)
    log.info("[%s] Scan started (profile=%s)", scan_id, req.profile)

    try:
        cfg = cfg_mod.Config.load()
        cfg.scan.profile = req.profile
        if req.ports:
            cfg.scan.ports = req.ports

        # ── Phase 1: Discovery ─────────────────────────────────────────────────
        discovered = discover.discover(
            iface=req.iface or os.environ.get("RECONENGINE_IFACE") or None,
            network=req.target,
            timeout=cfg.scan.discovery_timeout,
        )
        ips = [h["ip"] for h in discovered]
        _update(hosts_found=len(ips))
        log.info("[%s] Discovered %d host(s)", scan_id, len(ips))

        if not ips:
            _update(
                status=ScanStatus.DONE,
                finished_at=datetime.datetime.now().isoformat(),
                duration="0s",
                hosts_scanned=0,
            )
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
                _update(hosts_scanned=len(scan_results))

        elapsed = time.monotonic() - t0
        m, s = divmod(int(elapsed), 60)
        duration = f"{m}m{s:02d}s"

        if not scan_results:
            _update(
                status=ScanStatus.DONE,
                finished_at=datetime.datetime.now().isoformat(),
                duration=duration,
            )
            return

        # ── Phase 3 (optional): PDF report ────────────────────────────────────
        report_file = None
        if not req.no_pdf:
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

        _update(
            status=ScanStatus.DONE,
            finished_at=datetime.datetime.now().isoformat(),
            duration=duration,
            report_file=report_file,
        )
        log.info("[%s] Done in %s", scan_id, duration)

    except Exception as exc:
        log.exception("[%s] Scan error: %s", scan_id, exc)
        _update(
            status=ScanStatus.ERROR,
            finished_at=datetime.datetime.now().isoformat(),
            error=str(exc),
        )


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"], summary="Liveness probe — no auth required")
def health() -> dict:
    running = sum(1 for s in _scans.values() if s["status"] == ScanStatus.RUNNING)
    return {"status": "ok", "scans_running": running}


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
    """
    # Limit to one concurrent scan (embedded hardware constraint)
    with _scans_lock:
        running = [s for s in _scans.values() if s["status"] == ScanStatus.RUNNING]
        if running:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A scan is already running (id={running[0]['scan_id']}). Wait for it to finish.",
            )

    scan_id = str(uuid.uuid4())[:8]
    entry: dict[str, Any] = {
        "scan_id":      scan_id,
        "status":       ScanStatus.PENDING,
        "profile":      req.profile,
        "started_at":   datetime.datetime.now().isoformat(),
        "finished_at":  None,
        "duration":     None,
        "hosts_found":  0,
        "hosts_scanned": 0,
        "report_file":  None,
        "error":        None,
    }
    with _scans_lock:
        _scans[scan_id] = entry

    background_tasks.add_task(_run_scan, scan_id, req)
    return ScanSummary(**entry)


@app.get(
    "/scans/{scan_id}",
    tags=["scans"],
    summary="Get scan status and results",
    response_model=ScanSummary,
)
def get_scan(_auth: AuthDep, scan_id: str) -> ScanSummary:
    with _scans_lock:
        entry = _scans.get(scan_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return ScanSummary(**entry)


@app.get(
    "/scans",
    tags=["scans"],
    summary="List all scans (most recent first)",
    response_model=list[ScanSummary],
)
def list_scans(_auth: AuthDep) -> list[ScanSummary]:
    with _scans_lock:
        entries = list(_scans.values())
    entries.sort(key=lambda e: e["started_at"], reverse=True)
    return [ScanSummary(**e) for e in entries]


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
    # Prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    cfg = cfg_mod.Config.load()
    path = pathlib.Path(cfg.output_dir) / filename
    if not path.exists() or path.suffix != ".pdf":
        raise HTTPException(status_code=404, detail=f"Report '{filename}' not found")
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
