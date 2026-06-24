# Copilot Instructions for i4g/ssi

**Unified Workspace Context:** This repository is part of the `i4g` multi-root workspace. Shared coding standards, routines, and platform context live in the `copilot/` repo. These instructions contain only repo-specific context.

## Environment

- **Conda env:** `i4g-ssi`
- **Language:** Python 3.13+ (FastAPI, Pydantic v2, Playwright)
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

## Coding Standards

Follow `copilot/.github/shared/general-coding.instructions.md` for all shared language standards.
