"""
lcd_driver.py — ST7789 display abstraction for ReconEngine.

Provides a high-level API to draw menus and status screens on a 240×240
ST7789 TFT over SPI. Rendering is done with Pillow (ImageDraw) and then
pushed to the hardware via the st7789 Pimoroni driver.

If the st7789 driver is not available (e.g. on a dev machine without SPI),
the module falls back to "headless" mode: frames are saved as PNG files in
/tmp/recon_lcd/ for visual debugging.
"""

from __future__ import annotations

import os
import logging
import textwrap
from pathlib import Path
from typing import List, Optional

from PIL import Image, ImageDraw, ImageFont

import lcd_config as cfg

log = logging.getLogger(__name__)


# ── Driver bootstrap ──────────────────────────────────────────────────────────

def _load_st7789():
    """Return an initialised ST7789 device, or None in headless mode."""
    try:
        import st7789

        device = st7789.ST7789(
            port=cfg.SPI_PORT,
            cs=cfg.SPI_DEVICE,
            dc=cfg.DC_PIN,
            rst=cfg.RST_PIN,
            backlight=cfg.BACKLIGHT_PIN,
            width=cfg.WIDTH,
            height=cfg.HEIGHT,
            rotation=cfg.ROTATION,
            spi_speed_hz=cfg.SPI_SPEED_HZ,
        )
        log.info("ST7789 driver initialised (%dx%d)", cfg.WIDTH, cfg.HEIGHT)
        return device
    except ImportError:
        log.warning("st7789 library not found — running in headless/PNG mode")
        return None
    except Exception as exc:  # SPI not available, wrong pins, etc.
        log.warning("ST7789 init failed (%s) — running in headless/PNG mode", exc)
        return None


# ── Font helpers ──────────────────────────────────────────────────────────────

def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    if cfg.FONT_PATH and Path(cfg.FONT_PATH).exists():
        try:
            return ImageFont.truetype(cfg.FONT_PATH, size)
        except Exception:
            pass
    return ImageFont.load_default()


# ── LCDDriver class ───────────────────────────────────────────────────────────

class LCDDriver:
    """High-level display interface for ReconEngine."""

    _HEADLESS_DIR = Path("/tmp/recon_lcd")

    def __init__(self) -> None:
        self._device = _load_st7789()
        self._headless = self._device is None
        if self._headless:
            self._HEADLESS_DIR.mkdir(parents=True, exist_ok=True)
            log.info("PNG frames → %s", self._HEADLESS_DIR)

        # Pre-load fonts
        self._font_title  = _load_font(cfg.FONT_SIZE_TITLE)
        self._font_item   = _load_font(cfg.FONT_SIZE_ITEM)
        self._font_status = _load_font(cfg.FONT_SIZE_STATUS)

        self._frame_count = 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _new_canvas(self) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        img = Image.new("RGB", (cfg.WIDTH, cfg.HEIGHT), cfg.COLOR_BG)
        draw = ImageDraw.Draw(img)
        return img, draw

    def _push(self, img: Image.Image, name: str = "frame") -> None:
        """Send image to hardware, or save as PNG in headless mode."""
        if not self._headless:
            self._device.display(img)
        else:
            path = self._HEADLESS_DIR / f"{name}_{self._frame_count:04d}.png"
            img.save(path)
            self._frame_count += 1
            log.debug("Frame saved: %s", path)

    def _text_size(self, text: str, font) -> tuple[int, int]:
        """Return (width, height) of text with given font (Pillow ≥ 10 API)."""
        dummy = Image.new("RGB", (1, 1))
        d = ImageDraw.Draw(dummy)
        bbox = d.textbbox((0, 0), text, font=font)
        return bbox[2] - bbox[0], bbox[3] - bbox[1]

    def _draw_header(self, draw: ImageDraw.ImageDraw, title: str) -> int:
        """Draw header bar; returns the y-offset after the bar."""
        bar_h = cfg.FONT_SIZE_TITLE + 12
        draw.rectangle([(0, 0), (cfg.WIDTH, bar_h)], fill=cfg.COLOR_HEADER)
        tw, th = self._text_size(title, self._font_title)
        tx = max(0, (cfg.WIDTH - tw) // 2)
        ty = (bar_h - th) // 2
        draw.text((tx, ty), title, font=self._font_title, fill=cfg.COLOR_TEXT)
        return bar_h + 2

    # ── Public API ────────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Fill the screen with the background colour."""
        img = Image.new("RGB", (cfg.WIDTH, cfg.HEIGHT), cfg.COLOR_BG)
        self._push(img, "clear")

    def draw_splash(self, title: str = "ReconEngine", subtitle: str = "Ready") -> None:
        """Full-screen splash / boot screen."""
        img, draw = self._new_canvas()

        # Centered title
        tw, th = self._text_size(title, self._font_title)
        draw.text(
            ((cfg.WIDTH - tw) // 2, cfg.HEIGHT // 2 - th - 8),
            title,
            font=self._font_title,
            fill=cfg.COLOR_HEADER,
        )
        # Subtitle
        sw, sh = self._text_size(subtitle, self._font_status)
        draw.text(
            ((cfg.WIDTH - sw) // 2, cfg.HEIGHT // 2 + 8),
            subtitle,
            font=self._font_status,
            fill=cfg.COLOR_DIM,
        )
        # Thin separator
        mid_y = cfg.HEIGHT // 2 - 2
        draw.line([(20, mid_y), (cfg.WIDTH - 20, mid_y)], fill=cfg.COLOR_DIM, width=1)

        self._push(img, "splash")

    def draw_menu(self, items: List[str], selected: int, title: str = "ReconEngine") -> None:
        """
        Render a vertical menu list.

        :param items:    List of menu item labels.
        :param selected: Currently highlighted index (0-based).
        :param title:    Header bar text.
        """
        img, draw = self._new_canvas()
        y = self._draw_header(draw, title)
        padding_x = 10
        row_h = cfg.FONT_SIZE_ITEM + 10

        for idx, label in enumerate(items):
            item_y = y + idx * row_h
            if item_y + row_h > cfg.HEIGHT:
                break  # Clamp to screen height

            is_selected = idx == selected

            # Highlight bar for selected item
            if is_selected:
                draw.rectangle(
                    [(0, item_y), (cfg.WIDTH, item_y + row_h - 2)],
                    fill=cfg.COLOR_SELECTED,
                )

            # Arrow indicator
            prefix = "▶ " if is_selected else "  "
            text_color = cfg.COLOR_BG if is_selected else cfg.COLOR_TEXT
            draw.text(
                (padding_x, item_y + 4),
                f"{prefix}{label}",
                font=self._font_item,
                fill=text_color,
            )

        self._push(img, "menu")

    def draw_status(
        self,
        title: str,
        message: str,
        color: Optional[tuple] = None,
        progress: Optional[int] = None,
    ) -> None:
        """
        Display a status screen with a title and multi-line message.

        :param title:    Bold header text.
        :param message:  Body text (auto-wrapped).
        :param color:    Text colour override (defaults to COLOR_WARN).
        :param progress: Optional 0–100 progress bar value.
        """
        if color is None:
            color = cfg.COLOR_WARN

        img, draw = self._new_canvas()
        y = self._draw_header(draw, "ReconEngine")

        # Title line
        y += 8
        draw.text((10, y), title, font=self._font_item, fill=color)
        y += cfg.FONT_SIZE_ITEM + 10

        # Wrapped message body
        max_chars = (cfg.WIDTH - 20) // max(1, cfg.FONT_SIZE_STATUS // 2)
        lines = []
        for raw_line in message.splitlines():
            lines.extend(textwrap.wrap(raw_line, max_chars) or [""])

        for line in lines:
            if y + cfg.FONT_SIZE_STATUS + 4 > cfg.HEIGHT - 20:
                draw.text((10, y), "…", font=self._font_status, fill=cfg.COLOR_DIM)
                break
            draw.text((10, y), line, font=self._font_status, fill=cfg.COLOR_TEXT)
            y += cfg.FONT_SIZE_STATUS + 4

        # Optional progress bar
        if progress is not None:
            bar_y = cfg.HEIGHT - 18
            bar_w = cfg.WIDTH - 20
            filled = int(bar_w * max(0, min(100, progress)) / 100)
            draw.rectangle([(10, bar_y), (cfg.WIDTH - 10, bar_y + 8)], outline=cfg.COLOR_DIM)
            if filled > 0:
                draw.rectangle([(10, bar_y), (10 + filled, bar_y + 8)], fill=color)

        self._push(img, "status")

    def draw_result(self, title: str, lines: List[str], success: bool = True) -> None:
        """
        Display a scrollable result summary (last N lines that fit the screen).

        :param title:   Header title.
        :param lines:   Result lines to display.
        :param success: Determines the colour of the title.
        """
        color = cfg.COLOR_OK if success else cfg.COLOR_ERR
        img, draw = self._new_canvas()
        y = self._draw_header(draw, "ReconEngine")
        y += 6

        draw.text((10, y), title, font=self._font_item, fill=color)
        y += cfg.FONT_SIZE_ITEM + 8

        row_h = cfg.FONT_SIZE_STATUS + 4
        available_rows = (cfg.HEIGHT - y) // row_h
        visible = lines[-available_rows:] if len(lines) > available_rows else lines

        for line in visible:
            draw.text((10, y), line[:38], font=self._font_status, fill=cfg.COLOR_TEXT)
            y += row_h

        self._push(img, "result")
