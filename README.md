# Scam Site Investigator (SSI)

AI-driven scam URL reconnaissance and evidence packaging for law enforcement.

## What It Does

Given a suspicious URL, SSI automatically:

1. **Passive Recon** — WHOIS, DNS, SSL, GeoIP, screenshot, DOM snapshot, form inventory, technology fingerprint
2. **Active Interaction** _(Phase 2)_ — AI agent navigates scam funnels with synthetic PII, recording every step
3. **Evidence Packaging** — Generates prosecution-ready evidence packages (JSON + screenshots + HAR + network logs)

## Quick Start

```bash
# Install in development mode
pip install -e ".[dev,test]"

# Install Playwright browser
playwright install chromium

# Run the CLI
ssi investigate url "https://suspicious-site.example.com" --passive

# Run the API server
uvicorn ssi.api.app:app --reload --port 8100

# Run tests
pytest tests/unit -v
```

## Project Structure

```
ssi/
├── config/                  # TOML settings files
├── docker/                  # Dockerfiles for API and job images
├── src/ssi/
│   ├── api/                 # FastAPI REST API + web interface
│   ├── browser/             # Playwright-based page capture
│   ├── cli/                 # Typer CLI (entry point: `ssi`)
│   ├── identity/            # Synthetic PII vault (Faker-based)
│   ├── investigator/        # Core investigation orchestrator
│   ├── models/              # Pydantic domain models
│   ├── osint/               # OSINT modules (WHOIS, DNS, SSL, GeoIP, VT)
│   └── settings/            # Pydantic-settings configuration
├── tests/
│   ├── unit/
│   └── integration/
└── pyproject.toml
```

## Configuration

Settings follow the same layered pattern as the i4g core platform:

1. `config/settings.default.toml` — Defaults
2. `config/settings.{env}.toml` — Environment-specific overrides
3. `config/settings.local.toml` — Local developer overrides (gitignored)
4. Environment variables (`SSI_*` with `__` for nesting)
5. CLI flags

### Key Environment Variables

| Variable                        | Description                               | Default         |
| ------------------------------- | ----------------------------------------- | --------------- |
| `SSI_ENV`                       | Environment name (`local`, `dev`, `prod`) | `local`         |
| `SSI_LLM__PROVIDER`             | LLM provider (`ollama`, `vertex`)         | `ollama`        |
| `SSI_LLM__MODEL`                | Model name                                | `llama3.3`      |
| `SSI_OSINT__VIRUSTOTAL_API_KEY` | VirusTotal API key                        | _(empty)_       |
| `SSI_OSINT__IPINFO_TOKEN`       | ipinfo.io token                           | _(empty)_       |
| `SSI_BROWSER__HEADLESS`         | Run browser headless                      | `true`          |
| `SSI_EVIDENCE__OUTPUT_DIR`      | Evidence output directory                 | `data/evidence` |

## CLI Usage

```bash
# Investigate a single URL (passive only)
ssi investigate url "https://example.com" --passive

# Full investigation with active agent interaction
ssi investigate url "https://example.com"

# Batch investigation from file
ssi investigate batch urls.txt --output ./evidence

# Show resolved settings
ssi settings show

# Validate settings
ssi settings validate
```

## API Endpoints

| Method | Path                | Description                          |
| ------ | ------------------- | ------------------------------------ |
| `GET`  | `/health`           | Health check                         |
| `POST` | `/investigate`      | Submit URL for investigation (async) |
| `GET`  | `/investigate/{id}` | Check investigation status           |

## Integration with i4g Platform

SSI is designed as a standalone tool that integrates with i4g:

- **Fraud taxonomy** — Classification output maps to i4g's five-axis taxonomy
- **Evidence store** — Packages attach to existing case records
- **Ingestion trigger** — Scam URLs from victim reports auto-trigger SSI via workers
- **LEO reports** — SSI intelligence enriches dossier/LEO report pipeline

## License

MIT — See [LICENSE](LICENSE).
