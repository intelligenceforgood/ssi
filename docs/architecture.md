# SSI Architecture

> **Audience:** Developers and system architects. For end-user documentation, see the [docs site](../../docs/book/ssi/README.md).

> **Last Updated**: June 2025
> **Status**: Accepted

This document captures the key architecture decisions and system design for the Scam Site Investigator (SSI).

---

## System Overview

```
┌─────────────┐     ┌──────────────────────┐     ┌───────────────────┐
│  Web UI     │────▶│  SSI Orchestrator    │────▶│ Sandboxed Browser │
│  CLI / API  │     │  (FastAPI / Typer)   │     │ (zendriver)       │
└─────────────┘     └──────┬───────────────┘     └────────┬──────────┘
                           │                              │
         ┌─────────────────┼─────────────────┐            │
         │                 │                 │            │
  ┌──────▼───────┐  ┌──────▼─────┐  ┌────────▼────┐  ┌────▼────────────┐
  │ LLM Provider │  │ Cost       │  │ Playbook    │  │ Network Monitor │
  │ + Retry      │  │ Tracker    │  │ Engine      │  │ (HAR Recording) │
  │ (Ollama /    │  │ (Budget    │  │ (JSON       │  └────┬────────────┘
  │  Gemini)     │  │  Enforce)  │  │  Playbooks) │       │
  └──────┬───────┘  └────────────┘  └─────────────┘       │
         │                                                │
  ┌──────▼───────┐  ┌──────────────┐  ┌──────────────┐    │
  │ Synthetic    │  │ Wallet       │  │ OSINT        │◀───┘
  │ PII Vault    │  │ Extraction   │  │ Enrichment   │
  │              │  │ (Regex + QR) │  │ + Retry      │
  └──────────────┘  └──────┬───────┘  │ (WHOIS, DNS, │
                           │          │  SSL, GeoIP, │
                    ┌──────▼───────┐  │  VT, urlscan)│
                    │ Scan Store   │  └──────┬───────┘
                    │ (SQLite /    │         │
                    │  PostgreSQL) │  ┌──────▼───────┐
                    └──────────────┘  │ Evidence     │
                                      │ Store +      │
                                      │ Report Gen   │
                                      │ (MD+PDF+STIX)│
                                      └──────────────┘
```

---

## Decision 1: Standalone Repo

**Choice**: Standalone `ssi/` repository within the i4g workspace, merged later as a dependency.

**Rationale**:

- SSI needs Playwright, Faker, and browser automation deps — very different from core's PaddleOCR/LangChain stack. A separate `pyproject.toml` avoids bloating core's environment.
- Independent CI/CD with no risk of breaking core's tests. Faster iteration during the prototype phase.
- SSI needs sandboxed browser environments (Playwright in Docker/gVisor), fundamentally different from core's FastAPI + worker model.
- Integration tests can hit real scam URLs without polluting core's CI.

**Merge strategy**: When ready, SSI becomes a Python package dependency of core. Core calls `from ssi.investigator.orchestrator import run_investigation`. SSI Cloud Run Job images remain separate because browser sandbox requirements differ.

---

## Decision 2: Shared GCP Projects

**Choice**: Use existing `i4g-dev` / `i4g-prod` GCP projects, not new dedicated projects.

**Rationale**:

- Zero setup — billing, IAM, VPC, Secret Manager already configured.
- Cloud Run services communicate without cross-project IAM.
- Reuse Artifact Registry, VPC egress, Secret Manager, IAM groups.

**Resource naming**: All SSI resources use `ssi-` prefix (`ssi-api`, `ssi-investigate-job`, `i4g-dev-ssi-evidence`). Terraform adds `ssi_*.tf` files alongside existing resources in `infra/environments/app/dev/`.

**Reconsider if**: SSI exceeds 5,000 investigations/month or requires dedicated network isolation for legal reasons.

---

## Decision 3: Improvements over Core Patterns

| Aspect         | Core (`i4g`)                             | SSI                                  | Why                                         |
| -------------- | ---------------------------------------- | ------------------------------------ | ------------------------------------------- |
| Python version | ≥3.10                                    | ≥3.11                                | `tomllib` in stdlib; better typing features |
| Linting        | Black + isort                            | Black + isort + Ruff + mypy strict   | Ruff is faster; mypy strict from day 1      |
| Type stubs     | No `py.typed`                            | `py.typed` included (PEP 561)        | Enables type checking for consumers         |
| Pre-commit     | Not in repo                              | `.pre-commit-config.yaml` committed  | Enforces formatting from first commit       |
| Settings       | Multi-file sections with runtime overlay | Single `config.py` with TOML merging | Less indirection, same power                |
| HTTP client    | `requests` (sync)                        | `httpx` (async-ready)                | Modern, async-capable                       |

**Patterns retained from core**: `src/` layout with hatchling, Typer CLI with subcommands, Pydantic settings with TOML + env var layering, FastAPI with CORS and health endpoint, Docker multi-stage builds, `VERSION.txt` for single-source version.

---

## Decision 4: CLI-First, Web-Second

**Choice**: CLI is the primary interface; API runs in parallel.

- `ssi investigate url <URL>` is the primary entry point
- FastAPI on port 8100 wraps the same `run_investigation()` function with background task semantics
- CLI enables rapid iteration, CI/CD integration, and batch testing against known scam patterns
- The API layer is intentionally thin — just request handling and status polling

---

## Decision 5: Package Namespace

**Choice**: `ssi` (top-level package), not `i4g.ssi`.

- Simpler imports: `from ssi.models import InvestigationResult`
- No namespace package complexity
- When integrated into core, SSI remains an external dependency, not a subpackage

---

## Component Stack

| Component          | Local                               | Production (GCP)                     |
| ------------------ | ----------------------------------- | ------------------------------------ |
| LLM                | Ollama (Llama 3.1)                  | Vertex AI Gemini 2.0 Flash           |
| LLM abstraction    | `ssi.llm.OllamaProvider`            | `ssi.llm.GeminiProvider`             |
| Browser automation | Playwright (local)                  | Playwright in Cloud Run Job (gVisor) |
| OSINT APIs         | Free tiers                          | Paid API keys in Secret Manager      |
| Synthetic PII      | Faker + local generation            | Same                                 |
| Evidence storage   | Local filesystem (`data/evidence/`) | Cloud Storage bucket                 |
| Orchestrator API   | FastAPI (local uvicorn)             | Cloud Run service                    |
| Web UI             | Built-in (Jinja2 templates)         | Same (served by Cloud Run service)   |
| Report generation  | Jinja2 templates + WeasyPrint PDF   | Same                                 |
| Cost tracking      | In-memory                           | Same (DB-backed in future)           |

---

## Investigation Pipeline

The orchestrator executes three phases sequentially, with cost budget gates
between phases to abort early if the investigation exceeds its cap.

### Phase 1 — Passive Reconnaissance

1. WHOIS/RDAP lookup (with retry)
2. DNS record resolution — A, AAAA, MX, TXT, NS, CNAME (with retry)
3. SSL/TLS certificate inspection (with retry)
4. GeoIP lookup via ipinfo.io (with retry)
5. Browser capture — screenshot, DOM, HAR, forms, external resources, redirects
6. VirusTotal URL reputation check (with retry)
7. urlscan.io page analysis (with retry)

**Budget gate** — if cost tracker reports budget exceeded, the investigation
skips Phase 2 and proceeds to evidence packaging.

### Phase 2 — Active Agent Interaction

1. Launch browser agent with LLM (Ollama or Gemini, wrapped in retry provider)
2. Generate synthetic identity for form filling
3. Execute observe → decide → act loop (configurable step limit and token budget):
   - **Observe**: extract numbered interactive elements from DOM
   - **Decide**: send observation to LLM, receive JSON action decision
   - **Act**: execute action (click, type, select, scroll, submit, navigate)
4. Track PII fields submitted, pages visited, downloads captured
5. Record per-step screenshots and session data

**Budget gate** — second check after HAR analysis.

### Phase 2.5 — Wallet Extraction

1. Scan all text sources for cryptocurrency wallet addresses:
   - Page snapshot DOM text
   - Agent step observations and filled values
   - QR/barcode decoded data from inline images
2. Match against 10+ blockchain patterns (BTC, ETH, TRX, SOL, XRP, ADA, LTC, DOGE, BCH, DASH)
3. Deduplicate and classify each address by token symbol
4. QR-decoded addresses receive higher confidence scores

### Phase 3 — Classification & Evidence Packaging

1. Five-axis fraud taxonomy classification via LLM
2. HAR analysis for IOCs (tracking domains, phishing-kit patterns, credential exfiltration, crypto addresses)
3. Generate evidence artifacts:
   - `investigation.json` — structured result
   - `report.md` — human-readable report
   - `leo_evidence_report.md` — law enforcement summary
   - `stix_bundle.json` — STIX 2.1 IOC bundle
   - `evidence.zip` — all artifacts with SHA-256 manifest
4. Persist results to ScanStore (SQLite / PostgreSQL)

---

## Security Model

- **Synthetic PII only** — SSN uses invalid 900–999 IRS range, credit cards use Stripe test BINs, email uses controlled `@i4g-probe.net` domain
- **Browser sandbox** — Playwright runs in headless mode with stealth scripts; production uses gVisor isolation
- **Anti-detection** — randomized fingerprints, proxy rotation, human-like interaction delays
- **No real PII** — SSI never processes or stores real personal information
- **Evidence integrity** — SHA-256 hashes for all artifacts in chain-of-custody manifest

---

## Configuration

Settings follow a layered precedence model (highest wins):

1. CLI flags
2. Environment variables (`SSI_*` with `__` for nesting)
3. `config/settings.local.toml` (gitignored)
4. `config/settings.{env}.toml`
5. `config/settings.default.toml`

Key configuration sections: `llm`, `browser`, `osint`, `evidence`, `identity`, `api`, `integration`, `stealth`, `captcha`, `cost`, `feedback`.

See the [Configuration page](../../docs/book/ssi/configuration.md) on the docs site for a complete environment variable reference.

---

## Hardening & Resilience

The following production-hardening features protect against runaway costs,
resource exhaustion, and transient external failures.

### Cost Budget Enforcement

`CostTracker` tracks per-investigation costs (LLM tokens, OSINT API calls,
compute seconds). A `check_budget()` method raises `BudgetExceededError`
between pipeline phases. The orchestrator catches this and marks the
investigation as completed-with-warning rather than failed — all data
collected before the budget trip is preserved.

Configuration: `SSI_COST__BUDGET_PER_INVESTIGATION_USD` (default: `1.0`).

### Concurrent Investigation Limit

The API enforces a configurable ceiling on simultaneous investigations via a
thread-safe counter in the routes layer. When at capacity, new requests
receive HTTP 429. The counter is decremented in a `finally` block to avoid
leaks on crashes.

Configuration: `SSI_API__MAX_CONCURRENT_INVESTIGATIONS` (default: `5`).

### LLM Retry with Backoff

`RetryingLLMProvider` wraps any `LLMProvider` with exponential-backoff retry
for transient network / provider errors (`ConnectionError`, `TimeoutError`,
HTTP 429/5xx). The factory wires this automatically — callers receive a
resilient provider without extra code.

### OSINT Retry Decorator

`ssi.osint.with_retries` is a shared decorator applied to all OSINT modules
(VirusTotal, urlscan, DNS, SSL, GeoIP). It retries on transient errors with
configurable backoff, matching the existing whois retry pattern.

### Error Sanitisation

API error responses return generic messages (e.g., "Internal investigation
error") instead of raw exception strings that might expose internal paths,
database connection strings, or API keys. Full details are logged server-side
only. Log messages for retries and provider errors use `type(e).__name__`
instead of `str(e)` to avoid leaking secrets in error messages.
