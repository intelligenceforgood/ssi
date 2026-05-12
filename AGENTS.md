# SSI — Repo Context

> **For the Antigravity Agent:** Auto-read this file when working in the `ssi/` repo. For platform-wide architecture and SSI↔Core integration, read `antigravity/knowledge/architecture/architecture.md`.

## Environment

- **Conda env:** `i4g-ssi`
- **Language:** Python 3.11+ (FastAPI, Pydantic v2, Playwright)
- **All commands prefix:** `conda run -n i4g-ssi ...`

## Build & Test

```bash
conda run -n i4g-ssi pip install -e ".[dev,test]"              # install editable
conda run -n i4g-ssi playwright install chromium               # install browser
conda run -n i4g-ssi uvicorn ssi.api.app:app --reload --port 8100  # dev server
conda run -n i4g-ssi pytest tests/unit                         # unit tests
conda run -n i4g-ssi make test                                 # all tests
```

## Architecture

- **Investigation entry point:** `src/ssi/investigator/orchestrator.py`
- Guard imports with `TYPE_CHECKING` to avoid runtime dependencies.

## Pre-Commit

```bash
conda run -n i4g-ssi pre-commit run --all-files   # Pass 1 — auto-fixes formatting
conda run -n i4g-ssi pre-commit run --all-files   # Pass 2 — must exit clean
```

- If a hook fails on Pass 2 that was not failing on Pass 1, troubleshoot the specific failure before retrying.

## Coding Conventions

- Python: full type hints, Google-style docstrings, Black/isort at 120-char lines
- For complete language standards, read `antigravity/knowledge/standards/python.md`
