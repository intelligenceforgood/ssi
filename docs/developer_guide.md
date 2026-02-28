# SSI Developer Guide

> **Audience:** Contributors and operators. For end-user documentation (CLI usage, playbooks, results), see the [docs site](../../docs/book/ssi/README.md).

This guide covers setting up a development environment, understanding the codebase, running tests, and contributing to the Scam Site Investigator.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Environment Setup](#2-environment-setup)
3. [Project Structure](#3-project-structure)
4. [Development Workflow](#4-development-workflow)
5. [Running Tests](#5-running-tests)
6. [Code Style & Linting](#6-code-style--linting)
7. [Configuration for Development](#7-configuration-for-development)
8. [Adding New Features](#8-adding-new-features)
9. [Docker Builds](#9-docker-builds)
10. [LLM Provider Configuration](#10-llm-provider-configuration)
11. [Web UI](#11-web-ui)
12. [GCP Deployment](#12-gcp-deployment)
13. [Make Targets](#13-make-targets)
14. [Hardening & Resilience](#14-hardening--resilience)

---

## 1. Prerequisites

- **Python 3.11+** — SSI requires 3.11 for `tomllib` and improved typing features
- **Ollama** — local LLM runtime ([ollama.com](https://ollama.com)). Install it, then pull a model:
  ```bash
  # macOS
  brew install ollama
  # Start the service (keep running in a dedicated terminal)
  ollama serve
  # Pull the default model (~2 GB download, runs well on 16 GB+ RAM)
  ollama pull llama3.3
  ```
- **Native libraries for PDF generation** — weasyprint requires GLib, Cairo, and Pango at the OS level. These cannot be installed via pip.

  ```bash
  # macOS — choose ONE of these methods:
  brew install glib cairo pango            # Homebrew
  conda install -c conda-forge glib cairo pango  # conda-forge (run inside your env)

  # Ubuntu / Debian
  sudo apt-get install libglib2.0-dev libcairo2-dev libpango1.0-dev
  ```

- **Git** — for version control

---

## 2. Environment Setup

### Step 1: Create a virtual environment

Choose whichever virtual environment tool you normally use. The project's conda environment is named `i4g-ssi`.

**Option A — conda / miniforge (recommended)**:

```bash
conda create -n i4g-ssi python=3.13
conda activate i4g-ssi
```

**Option B — built-in venv**:

```bash
python3 -m venv .venv
source .venv/bin/activate   # macOS / Linux
# .venv\Scripts\activate    # Windows
```

### Step 2: Install everything

```bash
# From the ssi/ directory — installs SSI + dev/test deps + Playwright browser
make setup
```

This runs `pip install -e ".[dev,test]"` (editable install with all extras) and installs the zendriver browser automation runtime. All Python dependencies are declared in `pyproject.toml` — there is no separate requirements file to manage.

### Step 3: Set up pre-commit hooks

```bash
pre-commit install
```

### Step 4: Verify installation

```bash
ssi --version
ssi settings validate
pytest tests/unit -v --tb=short
```

You should see:

```
✅ Settings valid
   Environment: local
   LLM provider: ollama
   Evidence dir: data/evidence
```

If Ollama is not running you will see a warning — start it with `ollama serve`.

---

## 2b. Running the Full Local Stack

To use the **web UI** (available at `http://localhost:3000/ssi`) you need two services running simultaneously:

| Service                   | Port | Purpose                            |
| ------------------------- | ---- | ---------------------------------- |
| **SSI API** (FastAPI)     | 8100 | Investigation engine, PDF reports  |
| **i4g console** (Next.js) | 3000 | Web UI that proxies to the SSI API |

Open **three** terminal tabs:

```bash
# Terminal 1 — Ollama (LLM runtime)
ollama serve

# Terminal 2 — SSI API server (hot reload)
conda activate i4g-ssi   # or source .venv/bin/activate
cd ssi/
make serve                # uvicorn ssi.api.app:app --reload --port 8100

# Terminal 3 — i4g console (Next.js)
cd ui/
pnpm dev                  # starts at http://localhost:3000
```

Then open `http://localhost:3000/ssi` in your browser. The SSI page is public (no auth required).

> **CLI-only usage**: If you just want the CLI and don't need the web UI, only Terminal 1 and 2 are needed. Run investigations with `ssi investigate url "<URL>" --passive`.

---

## 3. Project Structure

```
ssi/
├── config/                      # TOML settings files
│   ├── settings.default.toml    # Default configuration
│   └── settings.local.toml.example  # Template for local overrides
├── docker/
│   └── ssi-job.Dockerfile       # Cloud Run Job image
├── scripts/
│   ├── campaign_runner.py       # Batch campaign script
│   └── phase0_smoke.py          # Smoke test script
├── src/ssi/
│   ├── api/                     # FastAPI REST API
│   │   ├── app.py               # App factory, CORS, middleware
│   │   ├── routes.py            # /health, /investigate endpoints
│   │   ├── web.py               # Web UI routes (form + status)
│   │   └── web_templates/       # Jinja2 HTML templates
│   │       ├── index.html       # Investigation submission form
│   │       └── status.html      # Results + PDF download page
│   ├── browser/                 # zendriver browser automation
│   │   ├── actions.py           # Action executor (click, type, select, ...)
│   │   ├── agent.py             # LLM-driven browser interaction agent
│   │   ├── captcha.py           # CAPTCHA detection and handling
│   │   ├── capture.py           # Passive page capture
│   │   ├── dom_extractor.py     # DOM → numbered elements for LLM
│   │   ├── downloads.py         # File download interception
│   │   ├── har_analyzer.py      # HAR file IOC extraction
│   │   ├── llm_client.py        # LLM client (uses provider abstraction)
│   │   └── stealth.py           # Anti-detection / proxy rotation
│   ├── classification/          # Fraud taxonomy classification
│   │   ├── classifier.py        # Five-axis LLM classifier
│   │   └── prompts.py           # Classification prompt templates
│   ├── cli/                     # Typer CLI
│   │   ├── app.py               # Root app, wires subcommands
│   │   ├── investigate.py       # investigate url / batch commands
│   │   ├── job.py               # Cloud Run Job entry point
│   │   └── settings_cmd.py      # settings show / validate commands
│   ├── evidence/                # Evidence export
│   │   └── stix.py              # STIX 2.1 IOC bundle generation
│   ├── exceptions.py            # SSIError, BudgetExceededError, ConcurrentLimitError
│   ├── feedback/                # Investigation outcome tracking
│   ├── identity/                # Synthetic PII generation
│   │   └── vault.py             # Faker-based identity vault
│   ├── integration/             # i4g core platform bridge
│   │   └── core_bridge.py       # HTTP push to core API
│   ├── investigator/            # Investigation orchestration
│   │   └── orchestrator.py      # Main pipeline (passive → agent → package)
│   ├── llm/                     # LLM provider abstraction layer
│   │   ├── __init__.py          # Public exports
│   │   ├── base.py              # LLMProvider ABC + LLMResult
│   │   ├── factory.py           # create_llm_provider() factory + retry wrapping
│   │   ├── gemini_provider.py   # Google Gemini via Vertex AI
│   │   ├── ollama_provider.py   # Local Ollama provider
│   │   └── retry.py             # RetryingLLMProvider (exponential backoff)
│   ├── models/                  # Pydantic domain models
│   │   ├── agent.py             # AgentSession, AgentStep, ActionType
│   │   └── investigation.py     # InvestigationResult, WHOISRecord, etc.
│   ├── monitoring/              # Cost tracking & budget enforcement
│   │   ├── __init__.py          # CostTracker with check_budget()
│   │   ├── adapters.py          # Cloud Monitoring adapters
│   │   └── event_bus.py         # Async event bus
│   ├── osint/                   # Passive recon modules (all retry-decorated)
│   │   ├── __init__.py          # with_retries decorator
│   │   ├── dns_lookup.py
│   │   ├── geoip_lookup.py
│   │   ├── ssl_inspect.py
│   │   ├── urlscan.py
│   │   ├── virustotal.py
│   │   └── whois_lookup.py
│   ├── playbook/                # JSON playbook engine
│   │   ├── executor.py          # Step-by-step playbook runner
│   │   ├── loader.py            # TOML/JSON playbook loader
│   │   ├── matcher.py           # URL-to-playbook matching
│   │   └── models.py            # Playbook, PlaybookStep models
│   ├── reports/                 # Report generation
│   │   ├── __init__.py          # Jinja2 markdown renderer
│   │   └── pdf.py               # WeasyPrint PDF renderer
│   ├── settings/                # Pydantic settings with TOML layering
│   │   └── config.py
│   ├── store/                   # Scan result persistence
│   │   └── scan_store.py        # SQLAlchemy-backed ScanStore
│   ├── wallet/                  # Cryptocurrency wallet extraction
│   │   ├── allowlist.py         # Known-good wallet allowlist
│   │   ├── export.py            # Wallet export / serialization
│   │   ├── models.py            # WalletAddress, WalletChain models
│   │   └── patterns.py          # Regex patterns for BTC/ETH/TRX/SOL/...
│   └── worker/                  # Cloud Run Job runner
│       └── jobs.py
├── templates/                   # Jinja2 report templates
│   ├── report.md.j2
│   └── leo_report.md.j2
├── tests/
│   ├── unit/
│   └── integration/
├── Makefile
└── pyproject.toml
```

### Key entry points

| What                   | Where                                  |
| ---------------------- | -------------------------------------- |
| CLI entry point        | `src/ssi/cli/app.py`                   |
| Investigation pipeline | `src/ssi/investigator/orchestrator.py` |
| API server             | `src/ssi/api/app.py`                   |
| Settings               | `src/ssi/settings/config.py`           |
| Domain models          | `src/ssi/models/investigation.py`      |
| Wallet extraction      | `src/ssi/wallet/patterns.py`           |
| Cost tracker           | `src/ssi/monitoring/__init__.py`       |
| LLM retry wrapper      | `src/ssi/llm/retry.py`                 |
| Playbook engine        | `src/ssi/playbook/executor.py`         |
| Scan persistence       | `src/ssi/store/scan_store.py`          |
| Custom exceptions      | `src/ssi/exceptions.py`                |

---

## 4. Development Workflow

### Start the local services

Keep Ollama and the SSI API server running in separate terminals (see [§2b](#2b-running-the-full-local-stack) above).

### Run a quick investigation

```bash
ssi investigate url "https://example.com" --passive
```

### Typical development cycle

1. Make changes in `src/ssi/`
2. Run `make format` to auto-format
3. Run `make lint` to check for issues
4. Run `make test` for unit tests
5. Test manually with `ssi investigate url ...`
6. Commit (pre-commit hooks run automatically)

---

## 5. Running Tests

```bash
# Unit tests only (fast)
make test
# or: pytest tests/unit -v

# All tests including integration
make test-all
# or: pytest -v

# With coverage report
pytest tests/unit -v --cov=ssi --cov-report=term-missing

# Run a specific test file
pytest tests/unit/test_osint.py -v

# Run tests matching a keyword
pytest tests/unit -k "whois" -v
```

### Integration tests

Integration tests live in `tests/integration/` and exercise cross-module behaviour (end-to-end pipeline, API routes, wallet extraction against HTML fixtures). They are marked with `@pytest.mark.integration`.

```bash
# Run integration tests only
pytest tests/integration/ -v

# Run a specific integration suite
pytest tests/integration/test_wallet_extraction.py -v
```

HTML fixture pages for wallet extraction tests are in `tests/fixtures/scam_sites/`. Integration tests mock external network calls but exercise real OSINT parsing, wallet regex, and persistence logic.

> **Custom markers**: `integration` (cross-module tests) and `slow` (long-running tests) are registered in `conftest.py`. Filter with `-m "not slow"` for fast feedback loops.

---

## 6. Code Style & Linting

SSI uses strict tooling from day 1:

| Tool      | Purpose                        | Config                                   |
| --------- | ------------------------------ | ---------------------------------------- |
| **Black** | Code formatting                | `line-length = 120`                      |
| **isort** | Import sorting                 | `profile = "black"`, `line_length = 120` |
| **Ruff**  | Fast linting (replaces flake8) | Select: E, F, I, N, W, UP, B, SIM        |
| **mypy**  | Static type checking           | `strict = true`                          |

### Run all checks

```bash
# Auto-format
make format
# or: black src/ tests/ && isort src/ tests/

# Lint + type check
make lint
# or: ruff check src/ tests/ && mypy src/
```

### Pre-commit hooks

Pre-commit is configured in `.pre-commit-config.yaml` and runs Black, isort, and Ruff on every commit. Install with:

```bash
pre-commit install
```

---

## 7. Configuration for Development

Copy the example config and customize:

```bash
cp config/settings.local.toml.example config/settings.local.toml
```

Useful development overrides in `config/settings.local.toml`:

```toml
[browser]
headless = false    # Watch the browser during investigations

[llm]
temperature = 0.1
model = "llama3.3"

[osint]
virustotal_api_key = "your-key"       # Optional but enables VT checks
ipinfo_token = "your-token"           # Optional, free tier works without it

[cost]
enabled = false                        # Disable cost tracking locally
```

All settings can also be overridden via environment variables:

```bash
export SSI_BROWSER__HEADLESS=false
export SSI_LLM__MODEL=llama3.3
```

---

## 8. Adding New Features

### Adding a new OSINT module

1. Create `src/ssi/osint/your_module.py`
2. Implement an async function that takes a URL/domain and returns structured data
3. Add the result type to `src/ssi/models/investigation.py`
4. Wire it into `src/ssi/investigator/orchestrator.py` in the passive recon phase
5. Add a `--skip-yourmodule` flag to the CLI in `src/ssi/cli/investigate.py`
6. Write unit tests in `tests/unit/`

### Adding a new report template

1. Create `templates/your_report.md.j2`
2. Add rendering logic in `src/ssi/reports/__init__.py`
3. Update the orchestrator to generate the new report

### Adding a new CLI command

1. Create `src/ssi/cli/your_command.py` with a Typer app
2. Register it in `src/ssi/cli/app.py` via `app.add_typer()`
3. Document it in the user guide

---

## 9. Docker Builds

One Docker image is provided for the SSI Cloud Run Job:

```bash
# Cloud Run Job image
make build-job
# or: docker build -f docker/ssi-job.Dockerfile -t ssi-job .
```

The SSI API runs on the core gateway (see `core/docker/fastapi.Dockerfile`), so there is no separate SSI API image.

### Pushing to Artifact Registry

Build and push the job image to the `i4g-dev` Artifact Registry using the build script:

```bash
# Push Job image
make push-job
# or: scripts/build_image.sh ssi-job dev
```

Requires `gcloud` auth: `gcloud auth login` and `gcloud auth configure-docker us-central1-docker.pkg.dev`.

---

## 10. LLM Provider Configuration

SSI supports two LLM providers via a pluggable abstraction layer (see [src/ssi/llm/](../src/ssi/llm/)):

| Provider   | Local | Cloud | Model Example      |
| ---------- | ----- | ----- | ------------------ |
| **Ollama** | Yes   | —     | `llama3.1`         |
| **Gemini** | —     | Yes   | `gemini-2.0-flash` |

### Switching providers

Set the provider via environment variable or `config/settings.local.toml`:

```bash
# Ollama (default for local dev)
export SSI_LLM__PROVIDER=ollama

# Gemini (used on GCP)
export SSI_LLM__PROVIDER=gemini
export SSI_LLM__GCP_PROJECT=i4g-dev
export SSI_LLM__GCP_LOCATION=us-central1
export SSI_LLM__MODEL=gemini-2.0-flash
```

On Cloud Run, the Gemini provider authenticates via the service account's default credentials — no API key needed.

---

## 11. Web UI

SSI has two web interfaces:

### Built-in FastAPI UI (port 8100)

A minimal Jinja2 form served directly by the SSI API:

```bash
make serve   # http://localhost:8100/
```

### i4g Console UI (port 3000) — recommended

A polished Next.js page at `/ssi` in the i4g analyst console. It proxies requests to the SSI API so the user never contacts port 8100 directly.

```bash
# Terminal 1: SSI API
cd ssi/ && make serve

# Terminal 2: i4g Console
cd ui/ && pnpm dev
# Open http://localhost:3000/ssi
```

The `/ssi` route is **public** — it bypasses IAP authentication so anyone can submit a URL. Set `SSI_API_URL` in `ui/apps/web/.env.local` if the SSI API is running on a different host. Default: `http://localhost:8100`.

The UI provides:

- **Submit form** — enter a URL, click Investigate
- **Live status tracker** — 3-step progress (Queued → Analysing → Generating Report)
- **Result card** — risk score, fraud classification, threat indicators, WHOIS summary
- **PDF download / preview** — download or open the report in-browser

The web UI is served by FastAPI via Jinja2 templates in [src/ssi/api/web_templates/](../src/ssi/api/web_templates/).

---

## 12. GCP Deployment

SSI runs on Google Cloud Run in the `i4g-dev` project alongside the core platform.

### Infrastructure

Terraform config lives in `infra/environments/app/dev/`:

- Service account `sa-ssi` with Vertex AI, Storage, Logging, Monitoring roles
- Cloud Run job `ssi-investigate` (long-running investigations)
- GCS bucket `i4g-dev-ssi-evidence` for evidence storage

SSI API endpoints are served by the core gateway Cloud Run Service (no separate SSI service).

### Deploy workflow

```bash
# 1. Build and push job image
cd ssi/
make push-job

# 2. Apply Terraform
cd ../infra/environments/app/dev/
terraform apply
```

### Environment variables on Cloud Run

The Cloud Run service receives `SSI_*` environment variables via Terraform (see `terraform.tfvars`). Key settings:

- `SSI_ENV=dev` — environment profile
- `SSI_LLM__PROVIDER=gemini` — use Gemini on GCP
- `SSI_LLM__MODEL=gemini-2.0-flash` — model selection
- `SSI_LLM__GCP_PROJECT=i4g-dev` — Vertex AI project
- `SSI_EVIDENCE__STORAGE_BACKEND=gcs` — cloud storage for evidence

---

## 13. Make Targets

| Target             | Description                               |
| ------------------ | ----------------------------------------- |
| `make setup`       | Full first-time setup (install + browser) |
| `make install`     | Editable install (`pip install -e .`)     |
| `make install-dev` | Dev + test deps + pre-commit hooks        |
| `make browsers`    | Install browser automation runtime        |
| `make test`        | Run unit tests                            |
| `make test-all`    | Run all tests (unit + integration)        |
| `make lint`        | Ruff check + mypy strict                  |
| `make format`      | Black + isort auto-format                 |
| `make serve`       | Start API server (hot reload, port 8100)  |
| `make investigate` | Quick investigate (set `URL=` variable)   |
| `make build-job`   | Build Job Docker image                    |
| `make push-job`    | Build + push Job image to Artifact Reg    |
| `make clean`       | Remove build artifacts and caches         |
| `make rehydrate`   | Copilot session bootstrap                 |

---

## 14. Hardening & Resilience

SSI includes several production-hardening features. See [architecture.md](architecture.md#hardening--resilience) for the full design.

### Cost budget enforcement

`CostTracker.check_budget()` raises `BudgetExceededError` when cumulative LLM + API spend exceeds the configured budget. Budget gates are placed between investigation phases so partial results are preserved rather than discarded.

```python
from ssi.monitoring import CostTracker
from ssi.exceptions import BudgetExceededError

tracker = CostTracker(budget_usd=2.0)
# ... record costs ...
tracker.check_budget()  # raises BudgetExceededError if over budget
```

### Concurrent investigation limit

The API enforces `max_concurrent_investigations` (default: 5, configurable via `SSI_API__MAX_CONCURRENT_INVESTIGATIONS`). When at capacity, new submissions receive HTTP 429. This prevents resource exhaustion on shared infrastructure.

### LLM retry with backoff

All LLM calls are automatically retried via `RetryingLLMProvider` (see [src/ssi/llm/retry.py](../src/ssi/llm/retry.py)). Retryable errors include connection failures and HTTP 429/5xx responses. The factory wires retry wrapping by default — no manual configuration needed.

### OSINT retry decorator

Each OSINT module is decorated with `@with_retries` (see [src/ssi/osint/**init**.py](../src/ssi/osint/__init__.py)), providing exponential-backoff retry for transient network errors. Configure per-module via the decorator arguments.

### Error sanitisation

API error responses never expose internal details (stack traces, file paths, connection strings). Log messages in retry paths use `type(exc).__name__` instead of `str(exc)` to avoid leaking sensitive data into log aggregation systems.
