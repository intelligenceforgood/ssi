# Copilot Instructions for i4g/ssi

**Unified Workspace Context:** This repository is part of the `i4g` multi-root workspace. The `core/` repository acts as the primary entry point for coding conventions and architectural standards. These instructions are synchronized to ensure consistent behavior across all roots.

1. **Rehydrate & Daily Loop** – Start every session by activating the conda environment (`conda run -n i4g-ssi ...` or `act i4g-ssi` in a new terminal). Then check `git status -sb`. Skim `planning/change_log.md` for recent decisions.
   - **Conda env:** `i4g-ssi`. All terminal commands for this repo must use `conda run -n i4g-ssi ...`.
   - **Plan:** Check active work stream in `planning/tasks/quality_elevation_plan.md`.
   - **Build:** Run `conda run -n i4g-ssi uvicorn ssi.api.app:app --reload --port 8100` for API; use `conda run -n i4g-ssi pip install -e ".[dev,test]"`.
   - **Test:** Run `conda run -n i4g-ssi pytest tests/unit` or targeted smoke tests. If skipping, record why.
   - **Docs:** Update `docs/` and `planning/change_log.md` when behavior/env vars change.
   - **Wrap-up:** Update `planning/change_log.md` with any significant progress.

2. **Config Discipline** – Fetch settings via `ssi.settings.get_settings()`; nested sections (`llm`, `browser`, `osint`, `evidence`, `identity`, `api`, `storage`) are overridden via env vars (`SSI_*`, double underscores for nesting). Store builders live in `src/ssi/store/`; use `build_scan_store()` for scan persistence.

3. **Coding Conventions** – Follow `core/.github/general-coding.instructions.md` for all language-specific standards. Python uses full type hints, Google-style docstrings, Black/isort at 120-char lines. Pydantic models use `snake_case` internally. For Playwright `Page` type on function parameters, guard the import with `TYPE_CHECKING` to avoid runtime dependency.

4. **Architecture** – `src/ssi/investigator/orchestrator.py` is the investigation entry point. `src/ssi/osint/` contains passive recon modules. `src/ssi/browser/` handles Playwright automation. `src/ssi/identity/vault.py` generates synthetic PII. `src/ssi/store/scan_store.py` persists scan results to SQLite or PostgreSQL. `src/ssi/integration/core_bridge.py` pushes findings to the core API.

5. **Developer Loop** – Conda env is `i4g-ssi`. Install editable (`conda run -n i4g-ssi pip install -e ".[dev,test]"`), then `conda run -n i4g-ssi playwright install chromium`. CLI entry point is `ssi`. Use `conda run -n i4g-ssi make test` for unit tests.

6. **Environment Profiles** – `SSI_ENV=local` uses Ollama + local filesystem. `dev`/`prod` target Vertex AI + GCS + Secret Manager on `i4g-dev`/`i4g-prod` GCP projects (shared with core).

7. **Data & Secrets** – Runtime artifacts live in `data/` (SQLite DB, evidence screenshots, session logs). Store non-public secrets in `.env.local` or platform secret managers. The wallet allowlist lives in `config/wallet_allowlist.json`.

8. **Docker Build Reference** – Use `scripts/build_image.sh` (requires `gcloud` auth). See `docker/` for Dockerfiles.

9. **External Integrations** – SSI pushes investigation results to the core API via `CoreBridge.push_investigation()`. This sends wallet indicators and OSINT entities to `/reviews/{id}/indicators` and `/reviews/{id}/entities`. Keep payloads in sync with core's API schemas.

10. **Repository Roles & Instruction Placement** – This workspace is multi-root. Keep per-repo instruction files in each repo's `.github/` directory.
    - `core/` — Primary Python + docs repo. Source of truth for shared conventions.
    - `ui/` — Node.js/Next.js UI repo.
    - `ssi/` — Scam-site investigation agent (this repo).
    - `planning/`, `docs/`, `infra/`, `mobile/`, `dtp/`, `agentic_wallet_harvester/` — Specialized components following `core` standards where applicable.

11. **Docs: code snippets policy** – Do NOT paste entire source files into markdown pages. Include a short, focused snippet (only the lines relevant to the doc) and add a repository link to the full file path.

12. **Infrastructure Alignment** – Terraform lives in the sibling `infra/` repo. Target `i4g-dev` before `i4g-prod`.

13. **Merge Readiness & Pre-Merge Review** – When the user requests a **pre-merge review**, execute the full checklist in `core/.github/pre-merge-review.instructions.md`. This includes: (a) coding standards audit against `core/.github/general-coding.instructions.md` — type hints on every function, Google-style docstrings on all public/private methods, no unused imports or dead code; (b) code quality — safe variable scoping, specific exception handling, no hard-coded secrets; (c) architecture alignment — correct use of stores/factories/settings; (d) test suite passes with zero failures; (e) docs/config updated if behavior changed. Produce a summary of issues found, fixes applied, test results, and remaining items.

14. **Env + Smoke Discipline** – Treat environment variables as a contract. When adding or changing settings: (a) add or update coverage under `tests/unit/` so overrides and defaults are validated locally, (b) refresh relevant docs, and (c) execute a local smoke test before any cloud deployment.

15. **UI Build Procedure** – To build the UI image, always change directory to the UI root first (`cd ui/`) and run the build script from there: `scripts/build_image.sh i4g-console dev`. Do not attempt to build from the workspace root.

16. **Entire Tool Integration** – The Entire tool tracks AI conversation context per commit in `.entire/` and `.claud/` folders. These folders are present in each repo root. `settings.json` is committed (shared config); `logs/`, `metadata/`, and `tmp/` are gitignored (local). Do NOT modify, delete, or overwrite files in `.entire/` or `.claud/` — they are managed exclusively by the Entire tool. During rehydration, read any available context from these folders to understand recent session history.
