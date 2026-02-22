# Scam Site Investigator (SSI)

AI-driven scam URL reconnaissance and evidence packaging for law enforcement.

Given a suspicious URL, SSI automatically:

1. **Passive Recon** — WHOIS, DNS, SSL, GeoIP, screenshot, DOM snapshot, form inventory, technology fingerprint
2. **Active Interaction** — AI agent navigates scam funnels with synthetic PII, recording every step
3. **Evidence Packaging** — generates prosecution-ready evidence packages (JSON, Markdown, STIX 2.1, ZIP with chain-of-custody)

## Quick Start

```bash
# Create and activate a virtual environment
conda create -n i4g-ssi python=3.11 && conda activate i4g-ssi
# or: python3.11 -m venv .venv && source .venv/bin/activate

# Install SSI
pip install -e ".[dev,test]"
playwright install chromium

# Ensure Ollama is running with Llama 3.3
ollama serve          # in a separate terminal
ollama pull llama3.3  # one-time download

# Run a passive investigation
ssi investigate url "https://suspicious-site.example.com" --passive

# Run a full investigation (AI agent interacts with the site)
ssi investigate url "https://suspicious-site.example.com"
```

## Documentation

### End-User Docs (docs site)

| Document                                        | Description                                                     |
| ----------------------------------------------- | --------------------------------------------------------------- |
| **[SSI Docs Site](../docs/book/ssi/README.md)** | Getting started, CLI usage, playbooks, wallets, troubleshooting |

### Developer Docs (this repo)

| Document                                             | Description                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| **[Developer Guide](docs/developer_guide.md)**       | Environment setup, codebase walkthrough, testing, contributing    |
| **[Architecture](docs/architecture.md)**             | System design, decisions, component stack, investigation pipeline |
| **[API Reference](docs/api_reference.md)**           | REST API endpoint contracts with request/response schemas         |
| **[Playbook Authoring](docs/playbook_authoring.md)** | Detailed JSON schema reference for playbook authors               |
| **[Batch Scheduling](docs/batch_scheduling.md)**     | Cloud Run Jobs, Cloud Scheduler, campaign runner                  |

### Planning & Roadmap (in planning repo)

| Document                                                                      | Description                                  |
| ----------------------------------------------------------------------------- | -------------------------------------------- |
| [PRD](../planning/prd_scam_site_investigator.md)                              | Product requirements and success criteria    |
| [Next Steps](../planning/proposals/ssi_next_steps.md)                         | Roadmap: local → GCP → platform integration  |
| [Original Proposal](../planning/proposals/scam_site_investigator.md)          | Initial proposal (historical reference)      |
| [Architecture Decisions](../planning/proposals/ssi_architecture_decisions.md) | Original ADR document (historical reference) |

## CLI Reference

```bash
ssi investigate url <URL> [--passive] [--format json|markdown|both] [--output DIR]
                         [--skip-whois] [--skip-virustotal] [--skip-urlscan] [--skip-screenshot]
                         [--push-to-core] [--trigger-dossier]

ssi investigate batch <FILE> [--passive] [--output DIR]

ssi job investigate --url <URL> [--passive] [--push-to-core] [--trigger-dossier]

ssi settings show
ssi settings validate
```

## API Endpoints

| Method | Path                | Description                        |
| ------ | ------------------- | ---------------------------------- |
| `GET`  | `/health`           | Health check                       |
| `POST` | `/investigate`      | Submit URL for async investigation |
| `GET`  | `/investigate/{id}` | Check investigation status         |

Start the API: `uvicorn ssi.api.app:app --reload --port 8100`

## License

MIT — See [LICENSE](LICENSE).
