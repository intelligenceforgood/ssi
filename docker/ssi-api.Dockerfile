# syntax=docker/dockerfile:1

# SSI API service image.
# Runs the FastAPI server with WebSocket support for live investigation
# monitoring and guidance. Includes both Playwright (passive recon) and
# Chromium (zendriver active agent) browser engines.
#
# NOTE: This image runs as root because Chromium requires --no-sandbox on
# Cloud Run.  The sandbox flag is disabled in settings.dev.toml.

FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SSI_PROJECT_ROOT=/app

WORKDIR /app

# System deps:
#   - WeasyPrint runtime (libpango, libcairo, etc.)
#   - libzbar0 for QR code detection (pyzbar)
#   - chromium for zendriver active-agent browser
#   - fonts-noto-cjk for East Asian scam sites
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
    libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info \
    fonts-liberation fonts-noto-cjk libzbar0 \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Point zendriver at the system Chromium
ENV SSI_ZEN_BROWSER__CHROME_BINARY=/usr/bin/chromium

# Copy project metadata first for pip cache layer
COPY pyproject.toml README.md VERSION.txt LICENSE ./

# Pre-install heavy GCP deps for Docker cache
RUN pip install --upgrade pip \
    && pip install --no-cache-dir \
    "google-cloud-aiplatform>=1.70.0,<3.0" \
    "google-cloud-storage" \
    "cloud-sql-python-connector[pg8000]>=1.12" \
    "pg8000" \
    "langchain" \
    "weasyprint"

# Copy source + config + templates
COPY src ./src
COPY config ./config
COPY templates ./templates

# Install the package (remaining deps)
RUN pip install --no-cache-dir .

# Install Playwright Chromium (used by passive recon scanner)
RUN playwright install chromium --with-deps

# Writable data directory for evidence, feedback, SQLite
RUN mkdir -p /app/data && chmod 755 /app/data

ENV SSI_ENV=dev

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health')" || exit 1

CMD ["uvicorn", "ssi.api.app:app", "--host", "0.0.0.0", "--port", "8100"]
