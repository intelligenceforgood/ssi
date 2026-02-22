# syntax=docker/dockerfile:1

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

# Copy all source + config + templates
COPY pyproject.toml README.md VERSION.txt LICENSE ./
COPY src ./src
COPY config ./config
COPY templates ./templates

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

# Install Playwright browsers
RUN playwright install chromium --with-deps

EXPOSE 8100

CMD ["uvicorn", "ssi.api.app:app", "--host", "0.0.0.0", "--port", "8100"]
