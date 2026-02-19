.PHONY: setup install install-dev test lint format clean browsers rehydrate

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

# ---------- Docker ----------
build-api:
	docker build -f docker/ssi-api.Dockerfile -t ssi-api:local .

build-job:
	docker build -f docker/ssi-job.Dockerfile -t ssi-job:local .

push-api:
	scripts/build_image.sh ssi-api dev

push-job:
	scripts/build_image.sh ssi-job dev

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
