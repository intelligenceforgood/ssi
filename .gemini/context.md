# Gemini Code Assist Context for i4g/ssi

**Unified Workspace Context:** This repository is part of the unified `i4g` parent workspace. Shared coding standards, routines, and platform context live in the `gemini` repo's styles directory (symlinked at the parent root). GCA will implicitly apply this file's context whenever you work within the `ssi/` directory.

## GCA Framework & Workflows

- **Agent Mode Management:** Keep Agent Mode **OFF** for standard queries, isolated code reviews, and planning to conserve quota. Toggle **ON** strictly for autonomous multi-file execution or terminal tasks.
- **Standardized Prompts:** Use the standard VSCode snippets (`gca-plan`, `gca-prd`, `gca-impl`, `gca-work`) to trigger routine workflows.
- **Global Standards:** Broad coding conventions are referenced from `.gemini/styles/` (symlinked to the `gemini` repository).

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

Follow the rules in `.gemini/styles/` for all shared language standards.
