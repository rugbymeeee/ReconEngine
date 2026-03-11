"""
lcd_menu.py — Interactive ST7789 LCD menu for ReconEngine.

Entry point for Raspberry Pi deployments. Displays a navigable menu on the
ST7789 TFT screen, starts scans/reports on button confirmation and shows
live status & results on-screen.

Run with:
    python lcd_menu.py

Navigation:
    BTN_UP    — move cursor up
    BTN_DOWN  — move cursor down
    BTN_ENTER — confirm selection (long-press returns to main menu)
    Ctrl+C    — graceful shutdown

The Rich console output used by scan.py / discover.py is kept active; if a
terminal is attached you will see the same detailed tables as running main.py.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import List, Optional

import docker.tools.gpio_lcd.lcd_config as cfg
import docker.tools.gpio_lcd.lcd_driver as lcd_driver
import docker.tools.gpio_lcd.gpio_input as gpio_input
import discover
import scan

log = logging.getLogger(__name__)

# ── Menu definition ───────────────────────────────────────────────────────────

MENU_ITEMS: List[str] = [
    "1. Découverte du réseau",
    "2. Analyse des ports",
    "3. Recherche d'exploits",
    "4. Pipeline complet",
    "5. Quitter",
]

# Map menu index → handler function (assigned after function definitions)
_HANDLERS: dict[int, callable] = {}


# ── Controller ────────────────────────────────────────────────────────────────

class MenuController:
    """Manages the navigation state and dispatches actions."""

    def __init__(self, display: lcd_driver.LCDDriver) -> None:
        self._display = display
        self._selected = 0
        self._items = MENU_ITEMS

    # ── Navigation helpers ────────────────────────────────────────────────

    def _prev(self) -> None:
        self._selected = (self._selected - 1) % len(self._items)

    def _next(self) -> None:
        self._selected = (self._selected + 1) % len(self._items)

    def _render(self) -> None:
        self._display.draw_menu(self._items, self._selected)

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> None:
        """Blocking event loop — returns only when the user selects Quit."""
        self._render()

        while True:
            action = gpio_input.wait_for_long_press()

            if action == "up":
                self._prev()
                self._render()

            elif action == "down":
                self._next()
                self._render()

            elif action == "enter":
                self._dispatch(self._selected)
                # Re-render menu after returning from handler
                self._render()

            elif action == "enter_long":
                # Long-press on main menu does nothing (no parent menu)
                pass

    # ── Dispatcher ────────────────────────────────────────────────────────

    def _dispatch(self, idx: int) -> None:
        handler = _HANDLERS.get(idx)
        if handler is None:
            self._display.draw_status("Error", f"No handler for item {idx}", color=cfg.COLOR_ERR)
            time.sleep(2)
            return
        try:
            handler(self._display)
        except KeyboardInterrupt:
            # Ctrl+C inside a handler cancels the action and returns to menu
            self._display.draw_status("Cancelled", "Returning to menu…", color=cfg.COLOR_DIM)
            time.sleep(1)
        except Exception as exc:
            log.exception("Handler %d raised an exception", idx)
            self._display.draw_status(
                "Error",
                str(exc),
                color=cfg.COLOR_ERR,
            )
            time.sleep(3)


# ── Action handlers ───────────────────────────────────────────────────────────

def _handle_discover(display: lcd_driver.LCDDriver) -> None:
    """Run ARP discovery and show found hosts on screen."""
    display.draw_status("Découverte…", "Envoi de sondes ARP\nVeuillez patienter…", progress=10)

    try:
        ips = discover.main()
    except SystemExit:
        ips = []

    if not ips:
        display.draw_status("Découverte", "Aucun hôte trouvé.", color=cfg.COLOR_WARN)
        time.sleep(3)
        return

    lines = [f"Found {len(ips)} host(s):"] + [f"  {ip}" for ip in ips]
    display.draw_result("Discovery Complete", lines, success=True)
    _wait_confirm(display)


def _handle_scan(display: lcd_driver.LCDDriver) -> None:
    """Discover hosts then port-scan each one."""
    display.draw_status("Scan", "Discovering hosts…", progress=5)

    try:
        ips = discover.main()
    except SystemExit:
        ips = []

    if not ips:
        display.draw_status("Scan", "No hosts to scan.", color=cfg.COLOR_WARN)
        time.sleep(3)
        return

    total = len(ips)
    result_lines: List[str] = []

    for idx, ip in enumerate(ips):
        pct = 5 + int(90 * idx / total)
        display.draw_status(
            "Scanning…",
            f"Host {idx + 1}/{total}\n{ip}",
            progress=pct,
        )

        data = scan.scan_host(ip)
        if data is None:
            result_lines.append(f"{ip}: no results")
            continue

        try:
            protocols = data.all_protocols()
        except Exception:
            protocols = []

        open_ports = sum(len(data[p]) for p in protocols)
        result_lines.append(f"{ip}: {open_ports} open port(s)")

    display.draw_result("Scan Complete", result_lines, success=True)
    _wait_confirm(display)


def _handle_exploits(display: lcd_driver.LCDDriver) -> None:
    """Discover → scan → searchsploit, show exploit count per service."""
    display.draw_status("Exploits", "Discovering hosts…", progress=5)

    try:
        ips = discover.main()
    except SystemExit:
        ips = []

    if not ips:
        display.draw_status("Exploits", "No hosts found.", color=cfg.COLOR_WARN)
        time.sleep(3)
        return

    result_lines: List[str] = []
    total = len(ips)

    for idx, ip in enumerate(ips):
        pct = 10 + int(80 * idx / total)
        display.draw_status("Exploit Search", f"Scanning {ip}…", progress=pct)

        data = scan.scan_host(ip)
        if data is None:
            result_lines.append(f"{ip}: no results")
            continue

        try:
            protocols = data.all_protocols()
        except Exception:
            protocols = []

        exploit_count = 0
        for proto in protocols:
            for port, pinfo in data[proto].items():
                query = " ".join(filter(None, [
                    pinfo.get("product") or "",
                    pinfo.get("version") or "",
                ])).strip() or pinfo.get("name", "")
                if query:
                    try:
                        exploits = scan.find_exploits(query)
                        exploit_count += len(exploits)
                    except Exception:
                        pass

        result_lines.append(f"{ip}: {exploit_count} exploit(s)")

    display.draw_result("Exploit Search Done", result_lines, success=True)
    _wait_confirm(display)


def _handle_full_pipeline(display: lcd_driver.LCDDriver) -> None:
    """Full pipeline: discover → scan → exploits — mirrors main.py logic."""
    display.draw_status("Full Pipeline", "Step 1/3\nDiscovering hosts…", progress=5)

    try:
        ips = discover.main()
    except SystemExit:
        ips = []

    if not ips:
        display.draw_status("Full Pipeline", "No hosts found.", color=cfg.COLOR_WARN)
        time.sleep(3)
        return

    result_lines: List[str] = []
    total = len(ips)

    for idx, ip in enumerate(ips):
        base_pct = 10 + int(85 * idx / total)
        display.draw_status(
            "Full Pipeline",
            f"Step 2/3 — Scanning\n{ip} ({idx + 1}/{total})",
            progress=base_pct,
        )

        data = scan.scan_host(ip)
        if data is None:
            result_lines.append(f"{ip}: no scan results")
            continue

        try:
            protocols = data.all_protocols()
        except Exception:
            protocols = []

        open_ports = sum(len(data[p]) for p in protocols)
        exploit_count = 0

        display.draw_status(
            "Full Pipeline",
            f"Step 3/3 — Exploits\n{ip}",
            progress=base_pct + 5,
        )

        for proto in protocols:
            for port, pinfo in data[proto].items():
                query = " ".join(filter(None, [
                    pinfo.get("product") or "",
                    pinfo.get("version") or "",
                ])).strip() or pinfo.get("name", "")
                if query:
                    try:
                        exploit_count += len(scan.find_exploits(query))
                    except Exception:
                        pass

        result_lines.append(f"{ip}: {open_ports} ports, {exploit_count} exploits")

    display.draw_result("Pipeline Complete", result_lines, success=True)
    _wait_confirm(display)


def _handle_quit(display: lcd_driver.LCDDriver) -> None:
    display.draw_status("Goodbye", "Shutting down…", color=cfg.COLOR_DIM)
    time.sleep(1)
    display.clear()
    raise SystemExit(0)


# Wire handlers to menu indices
_HANDLERS = {
    0: _handle_discover,
    1: _handle_scan,
    2: _handle_exploits,
    3: _handle_full_pipeline,
    4: _handle_quit,
}


# ── Utility ───────────────────────────────────────────────────────────────────

def _wait_confirm(display: lcd_driver.LCDDriver) -> None:
    """Show a 'Press ENTER to continue' hint and wait for the button."""
    # Overlay a small note at the bottom of the current frame by re-drawing
    display.draw_status(
        "Done",
        "Press ENTER to return\nto the main menu.",
        color=cfg.COLOR_OK,
    )
    gpio_input.wait_for_press()


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s",
    )

    display = lcd_driver.LCDDriver()
    gpio_input.setup()

    try:
        # Boot splash
        display.draw_splash("ReconEngine", "v1.0 — Ready")
        time.sleep(1.5)

        controller = MenuController(display)
        controller.run()

    except SystemExit as exc:
        sys.exit(int(str(exc)) if str(exc).isdigit() else 0)

    except KeyboardInterrupt:
        display.draw_status("Cancelled", "Keyboard interrupt.", color=cfg.COLOR_DIM)
        time.sleep(1)
        display.clear()
        sys.exit(0)

    finally:
        gpio_input.cleanup()


if __name__ == "__main__":
    main()
