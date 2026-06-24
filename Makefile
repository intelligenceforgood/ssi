.PHONY: setup install install-dev test lint format clean browsers rehydrate \
        build-svc build-dev deploy-dev build-prod deploy-prod

# macOS Apple Silicon Homebrew library path resolution for WeasyPrint
DYLD_ENV =
ifeq ($(shell uname -s),Darwin)
    ifeq ($(shell uname -m),arm64)
        DYLD_ENV = DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib
    endif
endif

# ---------- Setup ----------
# Full first-time setup: install Python deps + native libs + Playwright browser.
# Prerequisites: Python 3.13+ environment already activated (conda, venv, etc.).
# macOS native libs (required by weasyprint for PDF generation):
#   conda:  conda install -c conda-forge glib cairo pango
#   brew:   brew install glib cairo pango
#   NOTE: On Apple Silicon with Homebrew, you may also need to set the library path in your environment:
#   conda env config vars set DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib -n i4g-ssi
setup: install-dev browsers
	@echo "✅ Setup complete. Run 'ssi --version' to verify."

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,test]"
	pre-commit install

browsers:
	playwright install chromium

# ---------- Quality ----------
test:
	$(DYLD_ENV) pytest tests/unit -v

test-all:
	$(DYLD_ENV) pytest -v

lint:
	ruff check src/ tests/
	mypy src/ssi/

format:
	black src/ tests/
	isort src/ tests/

# ---------- Run ----------
serve:
	$(DYLD_ENV) uvicorn ssi.api.app:app --reload --port 8100

investigate:
	$(DYLD_ENV) ssi investigate $(URL)

# ---------- Docker / Deploy ----------
build-svc:
	docker build -f docker/ssi-svc.Dockerfile -t ssi-svc:local .

build-dev:
	scripts/build_image.sh ssi-svc dev

deploy-dev: build-dev
	gcloud run deploy ssi-svc \
		--image us-central1-docker.pkg.dev/i4g-dev/applications/ssi-svc:dev \
		--region us-central1 \
		--project i4g-dev

build-prod:
	scripts/build_image.sh ssi-svc prod \
		--registry us-central1-docker.pkg.dev/i4g-prod/applications

deploy-prod: build-prod
	gcloud run deploy ssi-svc \
		--image us-central1-docker.pkg.dev/i4g-prod/applications/ssi-svc:prod \
		--region us-central1 \
		--project i4g-prod

# ---------- Clean ----------
clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ---------- Rehydrate (Copilot session bootstrap) ----------
rehydrate:
	@echo "--- SSI Rehydrate ---"
	git status -sb
	@echo "--- Recent changes ---"
	git log --oneline -5 2>/dev/null || true
