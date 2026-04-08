"""
Shared pytest fixtures and path setup.

All tests in this suite cover pure Python logic — no network access,
no nmap, no searchsploit required.
"""
import sys
import pathlib

# Add docker/tools to sys.path so tests can import the modules directly.
TOOLS_DIR = pathlib.Path(__file__).parent.parent / "docker" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
