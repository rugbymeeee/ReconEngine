"""
lcd_config.py — Hardware configuration for the ST7789 display and GPIO buttons.

Edit these constants to match your physical wiring before launching lcd_menu.py.
All pin numbers use the BCM (Broadcom) numbering scheme.

ST7789 SPI wiring (standard Raspberry Pi SPI0):
  VCC  → 3.3V (pin 1)
  GND  → GND  (pin 6)
  SCL  → GPIO 11 / SCLK (pin 23)
  SDA  → GPIO 10 / MOSI (pin 19)
  RES  → GPIO 27 / RST  (pin 13)   ← DC_PIN below
  DC   → GPIO 25        (pin 22)   ← DC_PIN below (labelled DC on the PCB)
  CS   → GPIO 8  / CE0  (pin 24)   ← via SPI_DEVICE
  BLK  → GPIO 24        (pin 18)   ← BACKLIGHT_PIN (optional, can be tied to 3.3V)
"""

# ── ST7789 display ────────────────────────────────────────────────────────────

# SPI bus & chip-select device  (SPI0 → port=0, device=0  →  /dev/spidev0.0)
SPI_PORT: int = 0
SPI_DEVICE: int = 0
SPI_SPEED_HZ: int = 60_000_000  # 60 MHz — reduce to 40 MHz if you see glitches

# BCM pin numbers
DC_PIN: int = 25        # Data/Command selector
RST_PIN: int = 27       # Hardware reset (can be None if tied to 3.3V)
BACKLIGHT_PIN: int = 24 # Backlight PWM/GPIO  (None to skip backlight control)

# Display resolution
WIDTH: int = 240
HEIGHT: int = 240

# Rotation: 0, 90, 180, 270  (degrees)
ROTATION: int = 0

# ── GPIO buttons ─────────────────────────────────────────────────────────────
# Wired between the GPIO pin and GND (active-low, internal pull-up enabled).

BTN_UP: int = 17     # "Up" / previous item
BTN_DOWN: int = 22   # "Down" / next item
BTN_ENTER: int = 27  # "Select / Enter"

# Debounce window in milliseconds
DEBOUNCE_MS: int = 200

# Long-press threshold (ms) — used for "back" action in sub-menus
LONG_PRESS_MS: int = 1000

# ── UI colours (R, G, B) ──────────────────────────────────────────────────────
COLOR_BG: tuple = (0, 0, 0)           # Background
COLOR_HEADER: tuple = (0, 120, 255)   # Header bar
COLOR_SELECTED: tuple = (0, 200, 80)  # Selected item highlight
COLOR_TEXT: tuple = (255, 255, 255)   # Normal text
COLOR_DIM: tuple = (140, 140, 140)    # Dimmed / secondary text
COLOR_WARN: tuple = (255, 160, 0)     # Warning / in-progress
COLOR_OK: tuple = (0, 220, 80)        # Success
COLOR_ERR: tuple = (220, 50, 50)      # Error

# ── Typography ────────────────────────────────────────────────────────────────
# Path to a TrueType font. Falls back to Pillow's built-in bitmap font if None.
# On Raspberry Pi OS:  /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
FONT_PATH: str | None = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_SIZE_TITLE: int = 18
FONT_SIZE_ITEM: int = 15
FONT_SIZE_STATUS: int = 13
