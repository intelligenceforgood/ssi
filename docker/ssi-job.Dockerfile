# syntax=docker/dockerfile:1

# Job image for running SSI investigations as Cloud Run Jobs.
# Same base as the API but entrypoint is the CLI.

FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SSI_PROJECT_ROOT=/app

WORKDIR /app

# WeasyPrint runtime deps + libzbar0 for QR code detection (pyzbar)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
    libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info \
    fonts-liberation libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md VERSION.txt LICENSE ./
COPY src ./src
COPY config ./config
COPY templates ./templates

RUN pip install --upgrade pip && pip install --no-cache-dir .

RUN playwright install chromium --with-deps

# Run as a Cloud Run Job — reads SSI_JOB__URL and SSI_JOB__* env vars
ENTRYPOINT ["ssi", "job", "investigate"]
