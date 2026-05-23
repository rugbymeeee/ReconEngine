"""
LED status indicators for the ReconEngine PCB.

Drives 2× WS2812B (RGB adressables, LED1/LED2) + 2× LEDs discrètes 0402
(LED3 jaune, LED4 verte) câblées sur les GPIO de l'Orange Pi Zero 3.

Conception :
  - Import et init défensifs : si on tourne hors du PCB (dev machine, container
    sans /dev/gpiochip ou /dev/spidev), toutes les opérations deviennent no-op.
    Le code appelant n'a jamais à vérifier la disponibilité.
  - Thread daemon unique pour les animations (pulse, chase, blink).
  - Singleton process-wide — appelable depuis main.py et api.py.

Câblage (override via env) :
  - WS2812B DIN  ← SPI MOSI       (par défaut /dev/spidev1.0, à adapter au PCB)
  - LED jaune    ← GPIO line N°   (RECONENGINE_LED_YELLOW_GPIO)
  - LED verte    ← GPIO line N°   (RECONENGINE_LED_GREEN_GPIO)

  Les numéros GPIO sont des "line offsets" libgpiod sur /dev/gpiochip0.
  Adapter aux pins réellement routés sur la PCB.

Variables d'environnement :
  RECONENGINE_LED_ENABLED        "1" (défaut) | "0" pour désactiver
  RECONENGINE_LED_YELLOW_GPIO    Offset libgpiod LED jaune (défaut: 71)
  RECONENGINE_LED_GREEN_GPIO     Offset libgpiod LED verte  (défaut: 76)
  RECONENGINE_LED_GPIOCHIP       Chemin chip       (défaut: /dev/gpiochip0)
  RECONENGINE_WS2812_SPI         Chemin SPI        (défaut: /dev/spidev1.0)
    RECONENGINE_WS2812_SPI_HZ      SPI frequency     (defaut: 6400000)
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import threading
import time
from enum import Enum

log = logging.getLogger(__name__)


class State(Enum):
    IDLE          = "idle"           # tout éteint
    DISCOVERING   = "discovering"    # phase 1 — découverte ARP/ping
    SCANNING      = "scanning"       # phase 2 — scan nmap
    REPORTING     = "reporting"      # phase 4 — rendu PDF
    DONE_OK       = "done_ok"        # terminé, aucune critique
    DONE_CRITICAL = "done_critical"  # terminé, ≥1 critique
    ERROR         = "error"          # exception, pas de résultat utilisable


# ── Configuration ────────────────────────────────────────────────────────────
_ENABLED       = os.environ.get("RECONENGINE_LED_ENABLED", "1") != "0"
_GPIO_CHIP     = os.environ.get("RECONENGINE_LED_GPIOCHIP",  "/dev/gpiochip0")
_GPIO_YELLOW   = int(os.environ.get("RECONENGINE_LED_YELLOW_GPIO", "71"))
_GPIO_GREEN    = int(os.environ.get("RECONENGINE_LED_GREEN_GPIO",  "76"))
_SPI_PATH      = os.environ.get("RECONENGINE_WS2812_SPI",   "/dev/spidev1.0")

# WS2812B over SPI : 4 bits SPI par bit WS2812B
# SPI @ 6.4 MHz → période = 156 ns ; 4 bits = 625 ns par bit WS2812B (1.6 MHz)
# Encodage : "0" → 0b1000, "1" → 0b1110 (T0H≈156ns, T1H≈468ns — dans la tolérance)
def _parse_spi_hz(default: int) -> int:
    raw = os.environ.get("RECONENGINE_WS2812_SPI_HZ", "").strip()
    if not raw:
        return default
    try:
        hz = int(raw)
        return hz if hz > 0 else default
    except ValueError:
        return default


_SPI_HZ        = _parse_spi_hz(6_400_000)
_WS_RESET_BYTES = 50  # > 50 µs de 0 pour latcher les couleurs

_COLOR = {
    "off":    (0, 0, 0),
    "red":    (50, 0, 0),
    "green":  (0, 50, 0),
    "blue":   (0, 0, 50),
    "orange": (50, 20, 0),
    "yellow": (40, 40, 0),
    "white":  (40, 40, 40),
}


def _encode_byte(b: int) -> bytes:
    """Encode un octet WS2812B en 4 octets SPI (4 bits SPI par bit WS2812B)."""
    out = bytearray(4)
    for i in range(4):
        # On encode 2 bits WS2812B par octet SPI
        bit_hi = (b >> (7 - 2 * i)) & 1
        bit_lo = (b >> (6 - 2 * i)) & 1
        nibble_hi = 0b1110 if bit_hi else 0b1000
        nibble_lo = 0b1110 if bit_lo else 0b1000
        out[i] = (nibble_hi << 4) | nibble_lo
    return bytes(out)


def _encode_pixels(pixels: list[tuple[int, int, int]]) -> bytes:
    """Encode une liste de pixels (R,G,B) au format WS2812B (ordre GRB)."""
    buf = bytearray()
    for r, g, b in pixels:
        for chan in (g, r, b):  # WS2812B = GRB
            buf.extend(_encode_byte(chan & 0xFF))
    buf.extend(b"\x00" * _WS_RESET_BYTES)
    return bytes(buf)


# ── Drivers (import différé + fail-safe) ────────────────────────────────────

class _GPIO:
    """Wrapper libgpiod minimaliste. No-op si gpiod absent ou device introuvable."""

    def __init__(self) -> None:
        self._available = False
        self._lines: dict[int, object] = {}
        if not _ENABLED:
            return
        try:
            import gpiod
        except ImportError:
            log.debug("[status] gpiod non installé — LEDs discrètes désactivées")
            return
        if not os.path.exists(_GPIO_CHIP):
            log.debug("[status] %s introuvable — pas de PCB détectée", _GPIO_CHIP)
            return
        try:
            chip = gpiod.Chip(_GPIO_CHIP)
            for offset in (_GPIO_YELLOW, _GPIO_GREEN):
                line = chip.get_line(offset)
                line.request(consumer="reconengine", type=gpiod.LINE_REQ_DIR_OUT)
                self._lines[offset] = line
            self._available = True
            log.info("[status] LEDs discrètes prêtes (yellow=%d, green=%d)",
                     _GPIO_YELLOW, _GPIO_GREEN)
        except Exception as e:
            log.debug("[status] init GPIO impossible : %s", e)
            self._available = False

    def set(self, offset: int, on: bool) -> None:
        if not self._available:
            return
        line = self._lines.get(offset)
        if line is None:
            return
        with contextlib.suppress(Exception):
            line.set_value(1 if on else 0)

    def close(self) -> None:
        for line in self._lines.values():
            with contextlib.suppress(Exception):
                line.release()
        self._lines.clear()
        self._available = False


class _Neo:
    """Wrapper SPI pour 2× WS2812B. No-op si spidev absent."""

    NUM_LEDS = 2

    def __init__(self) -> None:
        self._available = False
        self._dev = None
        if not _ENABLED:
            return
        try:
            import spidev
        except ImportError:
            log.debug("[status] spidev non installé — WS2812B désactivés")
            return
        if not os.path.exists(_SPI_PATH):
            log.debug("[status] %s introuvable — WS2812B désactivés", _SPI_PATH)
            return
        try:
            # /dev/spidev1.0 → bus=1, device=0
            m = re.match(r"^/dev/spidev(\d+)\.(\d+)$", _SPI_PATH)
            if not m:
                log.debug("[status] SPI path invalide: %s", _SPI_PATH)
                return
            bus = int(m.group(1))
            dev = int(m.group(2))
            self._dev = spidev.SpiDev()
            self._dev.open(bus, dev)
            self._dev.max_speed_hz = _SPI_HZ
            self._dev.mode = 0
            self._available = True
            log.info("[status] WS2812B prêts via %s @ %d Hz", _SPI_PATH, _SPI_HZ)
        except Exception as e:
            log.debug("[status] init SPI impossible : %s", e)

    def show(self, color_left: tuple[int, int, int], color_right: tuple[int, int, int]) -> None:
        if not self._available or self._dev is None:
            return
        with contextlib.suppress(Exception):
            self._dev.writebytes2(_encode_pixels([color_left, color_right]))

    def close(self) -> None:
        if self._dev is not None:
            with contextlib.suppress(Exception):
                # éteindre avant de fermer
                self._dev.writebytes2(_encode_pixels([(0, 0, 0), (0, 0, 0)]))
                self._dev.close()
        self._dev = None
        self._available = False


# ── Driver principal (singleton) ────────────────────────────────────────────

class _Status:
    """État + thread d'animation. Thread-safe."""

    def __init__(self) -> None:
        self._state = State.IDLE
        self._lock  = threading.Lock()
        self._stop  = threading.Event()
        self._gpio  = _GPIO()
        self._neo   = _Neo()
        self._available = self._gpio._available or self._neo._available
        self._thread: threading.Thread | None = None
        if self._available:
            self._thread = threading.Thread(target=self._loop, name="led-status", daemon=True)
            self._thread.start()
        else:
            log.debug("[status] aucun matériel détecté — driver inactif")

    def set(self, state: State) -> None:
        with self._lock:
            if state is self._state:
                return
            self._state = state
            log.debug("[status] → %s", state.value)

    def shutdown(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        # forcer l'extinction
        self._neo.show(_COLOR["off"], _COLOR["off"])
        self._gpio.set(_GPIO_YELLOW, False)
        self._gpio.set(_GPIO_GREEN,  False)
        self._neo.close()
        self._gpio.close()

    # Animation loop — pas de busy-wait, tick fin pour les blinks
    def _loop(self) -> None:
        tick   = 0
        period = 0.10   # 100 ms — assez pour des pulse fluides et des blinks réactifs

        while not self._stop.is_set():
            with self._lock:
                state = self._state
            self._render(state, tick)
            tick += 1
            self._stop.wait(period)

    def _render(self, state: State, tick: int) -> None:
        # Calculs partagés
        slow_blink = (tick // 5) % 2 == 0     # ~500ms on/off
        fast_blink = (tick // 2) % 2 == 0     # ~200ms on/off
        # Pulse triangulaire simple sur 1.6s (16 ticks)
        pulse_pos  = tick % 16
        pulse      = pulse_pos if pulse_pos < 8 else 16 - pulse_pos  # 0..8..0
        pulse_lvl  = max(5, pulse * 8)

        if state is State.IDLE:
            self._neo.show(_COLOR["off"], _COLOR["off"])
            self._gpio.set(_GPIO_YELLOW, False)
            self._gpio.set(_GPIO_GREEN,  False)

        elif state is State.DISCOVERING:
            # WS2812B : pulse bleu sur les deux
            blue = (0, 0, pulse_lvl)
            self._neo.show(blue, blue)
            self._gpio.set(_GPIO_YELLOW, True)
            self._gpio.set(_GPIO_GREEN,  False)

        elif state is State.SCANNING:
            # WS2812B : chase orange (alterné)
            on  = _COLOR["orange"]
            off = _COLOR["off"]
            if fast_blink:
                self._neo.show(on, off)
            else:
                self._neo.show(off, on)
            self._gpio.set(_GPIO_YELLOW, False)
            self._gpio.set(_GPIO_GREEN,  slow_blink)

        elif state is State.REPORTING:
            # WS2812B : pulse blanc
            white = (pulse_lvl, pulse_lvl, pulse_lvl)
            self._neo.show(white, white)
            self._gpio.set(_GPIO_YELLOW, False)
            self._gpio.set(_GPIO_GREEN,  True)

        elif state is State.DONE_OK:
            self._neo.show(_COLOR["green"], _COLOR["green"])
            self._gpio.set(_GPIO_YELLOW, False)
            self._gpio.set(_GPIO_GREEN,  True)

        elif state is State.DONE_CRITICAL:
            self._neo.show(_COLOR["red"], _COLOR["red"])
            self._gpio.set(_GPIO_YELLOW, fast_blink)
            self._gpio.set(_GPIO_GREEN,  False)

        elif state is State.ERROR:
            # WS2812B : red blink + les deux LEDs blink
            col = _COLOR["red"] if slow_blink else _COLOR["off"]
            self._neo.show(col, col)
            self._gpio.set(_GPIO_YELLOW, slow_blink)
            self._gpio.set(_GPIO_GREEN,  slow_blink)


# ── API publique (singleton) ─────────────────────────────────────────────────
_driver: _Status | None = None
_driver_lock = threading.Lock()


def _get() -> _Status:
    global _driver
    if _driver is None:
        with _driver_lock:
            if _driver is None:
                _driver = _Status()
    return _driver


def set_state(state: State) -> None:
    """Met à jour l'état affiché. Sûr à appeler depuis n'importe quel thread."""
    _get().set(state)


def shutdown() -> None:
    """Éteint les LEDs et libère les handles GPIO/SPI. À appeler en fin de process."""
    global _driver
    with _driver_lock:
        if _driver is not None:
            try:
                _driver.shutdown()
            finally:
                _driver = None


# Petit helper de test manuel : `python status.py` cycle tous les états.
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")
    sequence = [
        (State.IDLE,          1.5),
        (State.DISCOVERING,   3.0),
        (State.SCANNING,      4.0),
        (State.REPORTING,     2.0),
        (State.DONE_OK,       2.5),
        (State.DONE_CRITICAL, 2.5),
        (State.ERROR,         2.5),
    ]
    try:
        for st, dur in sequence:
            print(f"→ {st.value}")
            set_state(st)
            time.sleep(dur)
    finally:
        shutdown()
