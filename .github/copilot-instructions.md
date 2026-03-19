# Copilot Instructions for i4g/ssi

**Unified Workspace Context:** This repository is part of the `i4g` multi-root workspace. Shared coding standards, routines, and platform context live in the `copilot/` repo. These instructions contain only repo-specific context.

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
- **Investigation entry point:** `src/ssi/investigator/orchestrator.py`
ts

ver
* * * * * * * * * * * * * * * * * t
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -ngs(- - - - - SI_*` - - - - - - - - - - - -core- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ist.- - - - - - - - - - - - - - - - - - - - - - - - - - � O- - - - - - - fil- - - m
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - pr- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -to- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - d - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

##########################################################################rs# guard the import with `TYPE_CHECKING` to avoid runtime dependency.

## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI �nda run ## i4g-ssi pre-commit run --all-files   ## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI �nda run ## i4g-ssi pre-commit run --all-files   ## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI �nda run ## i4g-ssi pre-commit run --all-files   ## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI — m## Pre-Commit (SSI �nda run ## i4g-ssi pre-commit run --all-files  exits with no files modified and all hooks passing.
- If a hook fails on Pass 2 that was not failing on Pass 1, troubleshoot the specific failure before retrying.

## Coding Standards

Follow `copilot/.github/shared/general-coding.instructions.md` for all shared language standards.
