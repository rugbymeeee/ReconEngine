# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1
# Keeps Python from buffering stdout and stderr.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies:
#   nmap            — port scanner (raw sockets, requires NET_RAW cap)
#   libpango*       — text rendering for WeasyPrint PDF output
#   libgdk-pixbuf   — image support for WeasyPrint
#   shared-mime-info — MIME detection for WeasyPrint
#   libpcap-dev     — raw packet capture for Scapy ARP discovery
#   exploitdb       — searchsploit (optional; enriches exploit data)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        exploitdb \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer cached until requirements.txt changes).
# Build context is repo root (see compose.yaml), so requirements.txt is reachable.
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# Install API server dependencies (FastAPI + Uvicorn).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "fastapi>=0.111" "uvicorn[standard]>=0.30" "pydantic>=2.7"

# Copy application source into the container.
COPY docker/tools/ ./tools/
COPY docker/tools/templates/ ./tools/templates/

# Create default report output directory.
RUN mkdir -p /app/rapports

# Expose the HTTP API port.
EXPOSE 8000

# Default: run the HTTP API server (port 8000).
# Override with CLI scan: docker run --rm --privileged --network host reconengine \
#   python tools/main.py full -i eth0
CMD ["python", "tools/api.py"]
