# syntax=docker/dockerfile:1

FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SSI_PROJECT_ROOT=/app

WORKDIR /app

# System deps for Playwright + headless Chromium
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libwayland-client0 \
    wget ca-certificates fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata
COPY pyproject.toml README.md VERSION.txt LICENSE ./

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

# Install Playwright browsers
RUN playwright install chromium --with-deps

# Copy source + config + templates
COPY src ./src
COPY config ./config
COPY templates ./templates

EXPOSE 8100

CMD ["uvicorn", "ssi.api.app:app", "--host", "0.0.0.0", "--port", "8100"]
