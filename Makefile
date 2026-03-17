.PHONY: setup install install-dev test lint format clean browsers rehydrate \
        build-svc build-dev deploy-dev build-prod deploy-prod

# ---------- Setup ----------
# Full first-time setup: install Python deps + native libs + Playwright browser.
# Prerequisites: Python 3.11+ environment already activated (conda, venv, etc.).
# macOS native libs (required by weasyprint for PDF generation):
#   conda:  conda install -c conda-forge glib cairo pango
#   brew:   brew install glib cairo pango
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
	pytest tests/unit -v

test-all:
	pytest -v

lint:
	ruff check src/ tests/
	mypy src/ssi/

format:
	black src/ tests/
	isort src/ tests/

# ---------- Run ----------
serve:
	uvicorn ssi.api.app:app --reload --port 8100

investigate:
	ssi investigate $(URL)

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
