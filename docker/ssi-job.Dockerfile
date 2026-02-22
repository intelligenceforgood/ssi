# syntax=docker/dockerfile:1

# Job image for running SSI investigations as Cloud Run Jobs.
# Same base system deps as the API but entrypoint is the CLI.
# Includes zendriver + Chromium for active browser agent and
# wallet extraction (coin tab discovery, JS regex, LLM verify).
#
# NOTE: Runs as root because Chromium requires --no-sandbox on Cloud Run.

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

# Run as a Cloud Run Job — reads SSI_JOB__URL and SSI_JOB__* env vars
ENTRYPOINT ["ssi", "job", "investigate"]
