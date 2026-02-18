# syntax=docker/dockerfile:1

# Job image for running SSI investigations as Cloud Run Jobs.
# Same base as the API but entrypoint is the CLI.

FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SSI_PROJECT_ROOT=/app

WORKDIR /app

# System deps for Playwright
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libwayland-client0 \
    wget ca-certificates fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md VERSION.txt LICENSE ./
RUN pip install --upgrade pip && pip install --no-cache-dir .

RUN playwright install chromium --with-deps

COPY src ./src
COPY config ./config
COPY templates ./templates

# Run as a Cloud Run Job — reads SSI_JOB__URL and SSI_JOB__* env vars
ENTRYPOINT ["ssi", "job", "investigate"]
