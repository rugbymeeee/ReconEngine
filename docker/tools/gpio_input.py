"""
gpio_input.py — GPIO button handler for ReconEngine LCD menu.

Manages three physical push-buttons (Up / Down / Enter) wired between
a BCM GPIO pin and GND. Internal pull-ups are enabled so no external
resistor is needed.

Usage (blocking):
    import gpio_input
    gpio_input.setup()
    press = gpio_input.wait_for_press()   # returns "up" | "down" | "enter"
    gpio_input.cleanup()

Usage (non-blocking poll):
    press = gpio_input.poll()             # returns action string or None

Run this file directly for a simple test:
    python gpio_input.py
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import lcd_config as cfg

log = logging.getLogger(__name__)

# ── RPi.GPIO bootstrap ────────────────────────────────────────────────────────

try:
    import RPi.GPIO as GPIO
    _HAS_GPIO = True
except ImportError:
    log.warning("RPi.GPIO not available — button input disabled (keyboard fallback active)")
    _HAS_GPIO = False


# ── Pin → action mapping ──────────────────────────────────────────────────────

_PIN_MAP: dict[int, str] = {
    cfg.BTN_UP:    "up",
    cfg.BTN_DOWN:  "down",
    cfg.BTN_ENTER: "enter",
}


# ── Setup / teardown ──────────────────────────────────────────────────────────

def setup() -> None:
    """Configure GPIO pins as inputs with pull-up resistors enabled."""
    if not _HAS_GPIO:
        return
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in _PIN_MAP:
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    log.info("GPIO buttons configured: UP=%d DOWN=%d ENTER=%d",
             cfg.BTN_UP, cfg.BTN_DOWN, cfg.BTN_ENTER)


def cleanup() -> None:
    """Release GPIO resources."""
    if _HAS_GPIO:
        GPIO.cleanup()
        log.info("GPIO cleanup done")


# ── Reading helpers ───────────────────────────────────────────────────────────

def _is_pressed(pin: int) -> bool:
    """Return True when pin reads LOW (button closed to GND)."""
    return GPIO.input(pin) == GPIO.LOW


def poll() -> Optional[str]:
    """
    Non-blocking scan of all buttons.

    Returns the action string ("up" / "down" / "enter") for the first pressed
    button, or None if no button is currently down.
    """
    if not _HAS_GPIO:
        return None
    for pin, action in _PIN_MAP.items():
        if _is_pressed(pin):
            return action
    return None


def wait_for_press(timeout: Optional[float] = None) -> Optional[str]:
    """
    Block until one button is pressed (and released) or timeout expires.

    Returns the action string, or None on timeout.
    A simple software debounce is applied (cfg.DEBOUNCE_MS).

    When GPIO is unavailable (dev machine) the function falls back to a
    keyboard readline so the menu can still be tested:
        Enter 'u' for UP, 'd' for DOWN, 'e'/'Enter' for ENTER.
    """
    if not _HAS_GPIO:
        return _keyboard_fallback(timeout)

    debounce_s = cfg.DEBOUNCE_MS / 1000.0
    start_time = time.monotonic()

    while True:
        if timeout is not None and (time.monotonic() - start_time) >= timeout:
            return None

        for pin, action in _PIN_MAP.items():
            if _is_pressed(pin):
                time.sleep(debounce_s)          # debounce wait
                if _is_pressed(pin):            # confirm still held
                    # Wait for release
                    while _is_pressed(pin):
                        time.sleep(0.01)
                    time.sleep(debounce_s)      # post-release debounce
                    log.debug("Button pressed: %s (GPIO %d)", action, pin)
                    return action

        time.sleep(0.01)  # 10 ms poll interval


def wait_for_long_press(timeout: Optional[float] = None) -> Optional[str]:
    """
    Like wait_for_press but distinguishes short vs long press.

    Returns "enter_long" for a long-press on the ENTER button,
    otherwise the same action strings as wait_for_press.
    """
    if not _HAS_GPIO:
        return _keyboard_fallback(timeout)

    debounce_s = cfg.DEBOUNCE_MS / 1000.0
    long_s = cfg.LONG_PRESS_MS / 1000.0
    start_time = time.monotonic()

    while True:
        if timeout is not None and (time.monotonic() - start_time) >= timeout:
            return None

        for pin, action in _PIN_MAP.items():
            if _is_pressed(pin):
                time.sleep(debounce_s)
                if not _is_pressed(pin):
                    continue  # spurious
                press_start = time.monotonic()
                while _is_pressed(pin):
                    time.sleep(0.01)
                duration = time.monotonic() - press_start
                if pin == cfg.BTN_ENTER and duration >= long_s:
                    return "enter_long"
                return action

        time.sleep(0.01)


# ── Keyboard fallback (dev/testing without hardware) ─────────────────────────

def _keyboard_fallback(timeout: Optional[float]) -> Optional[str]:
    """Interactive keyboard substitute for environments without GPIO."""
    _map = {"u": "up", "d": "down", "e": "enter", "": "enter"}
    prompt = "[gpio_input] No GPIO — press u/d/e + Enter: "
    if timeout is not None:
        print(f"{prompt}(timeout {timeout:.0f}s)")
    try:
        raw = input(prompt).strip().lower()
        return _map.get(raw, None)
    except (EOFError, KeyboardInterrupt):
        return None


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("GPIO button test — press Ctrl+C to exit")
    setup()
    try:
        while True:
            action = wait_for_press()
            print(f"→ {action}")
    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        cleanup()
