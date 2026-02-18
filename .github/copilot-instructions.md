# Copilot Instructions for i4g/ssi

**Unified Workspace Context:** This repository is part of the `i4g` multi-root workspace. The `core/` repository acts as the primary entry point for coding conventions and architectural standards. These instructions are synchronized to ensure consistent behavior across all roots.

1. **Rehydrate & Daily Loop** – Start every session by activating the conda environment (`conda run -n i4g-ssi ...` or `act i4g-ssi` in a new terminal). Then check `git status -sb`. Skim `planning/change_log.md` for recent decisions.
   - **Conda env:** `i4g-ssi`. All terminal commands for this repo must use `conda run -n i4g-ssi ...`.
   - **Plan:** Check active work stream in `planning/tasks/quality_elevation_plan.md`.
   - **Build:** Run `conda run -n i4g-ssi uvicorn ssi.api.app:app --reload --port 8100` for API; use `conda run -n i4g-ssi pip install -e ".[dev,test]"`.
   - **Test:** Run `conda run -n i4g-ssi pytest tests/unit` or targeted smoke tests. If skipping, record why.
   - **Docs:** Update `docs/` and `planning/change_log.md` when behavior/env vars change.

2. **Config Discipline** – Fetch settings via `ssi.settings.get_settings()`; nested sections (`llm`, `browser`, `osint`, `evidence`, `identity`, `api`) are overridden via env vars (`SSI_*`, double underscores for nesting).

3. **Coding Conventions** – Follow `core/.github/general-coding.instructions.md` for all language-specific standards. Python uses full type hints, Google-style docstrings, Black/isort at 120-char lines. Pydantic models use `snake_case` internally.

4. **Architecture** – `src/ssi/investigator/orchestrator.py` is the investigation entry point. `src/ssi/osint/` contains passive recon modules. `src/ssi/browser/` handles Playwright automation. `src/ssi/identity/vault.py` generates synthetic PII.

5. **Developer Loop** – Conda env is `i4g-ssi`. Install editable (`conda run -n i4g-ssi pip install -e ".[dev,test]"`), then `conda run -n i4g-ssi playwright install chromium`. CLI entry point is `ssi`. Use `conda run -n i4g-ssi make test` for unit tests.

6. **Environment Profiles** – `SSI_ENV=local` uses Ollama + local filesystem. `dev`/`prod` target Vertex AI + GCS + Secret Manager on `i4g-dev`/`i4g-prod` GCP projects (shared with core).

7. **Entire Tool Integration** – Do NOT modify `.entire/` or `.claud/` folders.
