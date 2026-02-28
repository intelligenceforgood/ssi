# SSI Technical Design Document

> **Audience:** Developers and system architects.
> **Last Updated**: February 22, 2026
> **Status**: Implemented (merge cycle complete)

This document is the canonical technical design reference for the Scam Site Investigator (SSI), covering architecture decisions, system design, data schema, API surface, deployment, and testing.

For end-user documentation, see the [docs site](../../docs/book/ssi/README.md).

---

## 1. System Overview

### 1.1 Component Architecture

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

### 1.2 Investigation Pipeline

The product is a **three-phase automated scam site investigation system**:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Analyst / Public User                          │
│                     Next.js UI (console + /ssi page)                     │
└───────────┬───────────────────┬──────────────────────┬───────────────────┘
            │ Submit URL        │ Monitor progress     │ Download evidence
            ▼                   ▼                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          SSI FastAPI Service                             │
│                          (Cloud Run / localhost:8100)                    │
│                                                                          │
│  POST /investigate          GET /investigate/{id}     GET /report/{id}   │
│  POST /investigate/batch    WS  /ws/monitor/{id}      GET /wallets/{id}  │
└───────┬──────────────────────┬───────────────────────┬───────────────────┘
        │                      │                       │
        ▼                      ▼                       ▼
┌─────────────────┐  ┌───────────────────┐  ┌──────────────────────────────┐
│ Phase 1         │  │ Phase 2           │  │ Phase 3                      │
│ Passive Recon   │  │ Active Interaction│  │ Intelligence Synthesis       │
│                 │  │                   │  │                              │
│ • WHOIS/RDAP    │  │ • State Machine   │  │ • Fraud Classification       │
│ • DNS           │  │   (zendriver)     │  │ • Evidence Packaging         │
│ • SSL/TLS       │  │ • DOM Inspector   │  │ • Report Generation          │
│ • GeoIP         │  │ • LLM Agent       │  │ • STIX 2.1 Bundle            │
│ • VirusTotal    │  │ • Wallet Extract  │  │ • Wallet Manifest            │
│ • urlscan.io    │  │ • Identity Vault  │  │ • PII Collection Map         │
│ • Screenshots   │  │ • Playbook Engine │  │                              │
│ • DOM/HAR       │  │ • Human Guidance  │  │                              │
└────────┬────────┘  └────────┬──────────┘  └────────────┬─────────────────┘
         │                    │                          │
         ▼                    ▼                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          Data Layer                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Relational   │  │ Evidence     │  │ Vector   │  │ PII Vault        │  │
│  │ SQLite / PG  │  │ FS / GCS     │  │ Chroma / │  │ (Isolated)       │  │
│  │              │  │              │  │ Vertex   │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────┘  └──────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

Each phase can run independently (passive-only, active-only, or full pipeline).

---

## 2. Architectural Decisions

### ADR-1: Standalone Repository

**Choice**: Standalone `ssi/` repository within the i4g workspace.

**Rationale**: SSI needs Playwright, Faker, zendriver, and browser automation deps — very different from core's stack. Separate `pyproject.toml` avoids bloating core's environment. Independent CI/CD with no risk of breaking core's tests. Integration tests can hit real scam URLs without polluting core's CI.

**Merge strategy**: SSI is a Python package dependency of core. Core calls `from ssi.investigator.orchestrator import run_investigation`. SSI Cloud Run Job images remain separate because browser sandbox requirements differ.

### ADR-2: Shared GCP Projects

**Choice**: Use existing `i4g-dev` / `i4g-prod` GCP projects.

**Rationale**: Zero setup — billing, IAM, VPC, Secret Manager already configured. Cloud Run services communicate without cross-project IAM. All SSI resources use `ssi-` prefix.

**Reconsider if**: SSI exceeds 5,000 investigations/month or requires dedicated network isolation.

### ADR-3: Improvements over Core Patterns

| Aspect         | Core (`i4g`)      | SSI                                 | Why                                    |
| -------------- | ----------------- | ----------------------------------- | -------------------------------------- |
| Python version | ≥3.10             | ≥3.11                               | `tomllib` in stdlib; better typing     |
| Linting        | Black + isort     | Black + isort + Ruff + mypy strict  | Ruff is faster; mypy strict from day 1 |
| Type stubs     | No `py.typed`     | `py.typed` included (PEP 561)       | Enables type checking for consumers    |
| Pre-commit     | Not in repo       | `.pre-commit-config.yaml` committed | Enforces formatting from first commit  |
| HTTP client    | `requests` (sync) | `httpx` (async-ready)               | Modern, async-capable                  |

**Patterns retained from core**: `src/` layout with hatchling, Typer CLI, Pydantic settings with TOML + env var layering, FastAPI with CORS, Docker multi-stage builds, `VERSION.txt`.

### ADR-4: CLI-First, Web-Second

**Choice**: CLI is the primary interface; API runs in parallel.

`ssi investigate url <URL>` is the primary entry point. FastAPI on port 8100 wraps the same `run_investigation()` function. Every capability must be CLI-accessible before it gets a UI surface. This ensures batch scheduling (cron, Cloud Scheduler) works without the UI.

| Surface             | Primary Use                           | Entry Point                        |
| ------------------- | ------------------------------------- | ---------------------------------- |
| `ssi` CLI           | Dev, analyst interactive, cron batch  | `orchestrator.run_investigation()` |
| SSI API + WebSocket | UI live monitoring, programmatic      | same orchestrator                  |
| `ssi job`           | Cloud Run Job (single URL per invoke) | same orchestrator                  |

### ADR-5: Package Namespace

**Choice**: `ssi` (top-level), not `i4g.ssi`.

Simpler imports: `from ssi.models import InvestigationResult`. No namespace package complexity. When integrated into core, SSI remains an external dependency, not a subpackage.

---

## 3. Technology Stack

### 3.1 Runtime Matrix

| Layer                 | Local                                    | Dev (GCP)                                 | Prod (GCP)                                 |
| --------------------- | ---------------------------------------- | ----------------------------------------- | ------------------------------------------ |
| **Python**            | 3.11+ (conda `i4g-ssi`)                  | Cloud Run container                       | Cloud Run container                        |
| **API**               | FastAPI + uvicorn (port 8100)            | Core gateway (Cloud Run)                  | Core gateway (Cloud Run)                   |
| **Browser (Active)**  | zendriver + Chromium (headless)          | Cloud Run Job (gVisor)                    | Cloud Run Job (gVisor)                     |
| **Browser (Passive)** | Playwright + Chromium                    | Cloud Run Job                             | Cloud Run Job                              |
| **LLM (text)**        | Ollama (Llama 3.3)                       | Vertex AI Gemini 2.0 Flash                | Vertex AI Gemini 2.0 Flash                 |
| **LLM (vision)**      | Ollama (Gemma 3 12B / Qwen3-VL 8B)       | Vertex AI Gemini 2.0 Flash                | Vertex AI Gemini 2.0 Flash                 |
| **LLM (escalation)**  | —                                        | Vertex AI Gemini 2.5 Pro                  | Vertex AI Gemini 2.5 Pro                   |
| **Relational DB**     | SQLite (`data/ssi_store.db`)             | Cloud SQL PostgreSQL 15                   | Cloud SQL PostgreSQL 15                    |
| **Evidence Storage**  | Local FS (`data/evidence/`)              | GCS bucket                                | GCS bucket                                 |
| **Proxy**             | Decodo residential (premium)             | Decodo residential (premium)              | Decodo residential (premium)               |
| **Secrets**           | `.env.local`                             | GCP Secret Manager                        | GCP Secret Manager                         |
| **Config**            | `settings.local.toml` + `SSI_*` env vars | `settings.dev.toml` + env vars            | `settings.prod.toml` + env vars            |
| **IaC**               | N/A                                      | Terraform (`infra/environments/app/dev/`) | Terraform (`infra/environments/app/prod/`) |

### 3.2 Key Dependencies

```toml
[project.dependencies]
# Web framework
fastapi = ">=0.115"
uvicorn = {version = ">=0.34", extras = ["standard"]}
websockets = ">=13.0"

# Browser automation
zendriver = ">=0.5"          # CDP-based undetected Chrome (active interaction)
playwright = ">=1.49"        # Feature-rich browser (passive capture, HAR)

# LLM providers
google-generativeai = ">=0.8"     # Gemini 2.0 Flash + 2.5 Pro

# OSINT
python-whois = ">=0.9"
dnspython = ">=2.7"
requests = ">=2.32"

# Data & models
pydantic = ">=2.10"
sqlalchemy = ">=2.0"
alembic = ">=1.14"

# Identity
faker = ">=33.0"

# Evidence & reports
jinja2 = ">=3.1"
weasyprint = ">=63.0"            # PDF generation
stix2 = ">=3.0"                  # STIX 2.1 threat intel
pillow = ">=11.0"                # Screenshot processing
openpyxl = ">=3.1"               # XLSX export

# GCP
google-cloud-storage = ">=2.18"
google-cloud-sql-connector = ">=1.12"

# Config
dynaconf = ">=3.2"               # Layered settings (TOML + env)
```

### 3.3 Dual-Engine Browser Architecture

The product runs **two browser engines** for different purposes:

```
┌──────────────────────────────────┐
│ zendriver (CDP, undetected)      │ ← Active interaction
│ • Registration form filling      │   (stealth matters)
│ • Deposit page navigation        │
│ • Wallet extraction              │
│ • Multi-step funnel traversal    │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│ Playwright (feature-rich)        │ ← Passive capture
│ • Full-page screenshots          │   (features matter)
│ • DOM snapshots                  │
│ • HAR network recording          │
│ • Download interception          │
│ • Form field inventory           │
└──────────────────────────────────┘
```

Both engines share the same proxy configuration and stealth settings. The orchestrator decides which engine to use based on the investigation phase.

---

## 4. Data Architecture

### 4.1 Schema Mapping to Core

Each scanned site is a **case** in the core database, enabling full integration with the analyst review queue, search, and dossier generation.

| Core Table         | SSI Usage                                            | Fit       |
| ------------------ | ---------------------------------------------------- | --------- |
| `cases`            | Each scam site = one case (`source_type="ssi_scan"`) | Excellent |
| `ingestion_runs`   | Each batch scan = one ingestion run                  | Good      |
| `campaigns`        | Group related scam sites                             | Good      |
| `source_documents` | Investigation JSON, screenshots, HAR, DOM            | Good      |
| `entities`         | Domains, IPs, registrants, SSL issuers               | Good      |
| `indicators`       | Wallet addresses, malicious IPs/domains/URLs         | Excellent |
| `review_queue`     | Flagged sites enter analyst review                   | Excellent |

### 4.2 New Tables

Four SSI-specific tables extend core's schema:

**`site_scans`** — Investigation metadata:

| Column           | Type     | Description                              |
| ---------------- | -------- | ---------------------------------------- |
| `scan_id` (PK)   | UUID     | Unique scan identifier                   |
| `case_id` (FK)   | UUID     | Link to core's cases table               |
| `scan_type`      | enum     | passive \| active \| full                |
| `scan_status`    | enum     | queued \| running \| completed \| failed |
| `passive_result` | JSONB    | WHOIS, DNS, SSL, GeoIP results           |
| `active_result`  | JSONB    | Agent session summary                    |
| `wallet_count`   | int      | Number of wallets extracted              |
| `classification` | JSONB    | Five-axis taxonomy result                |
| `risk_score`     | float    | 0–100 risk score                         |
| `evidence_path`  | str      | Path to evidence directory               |
| `cost_usd`       | float    | Total investigation cost                 |
| `llm_calls`      | int      | Number of LLM API calls                  |
| `tokens_used`    | int      | Total tokens consumed                    |
| `started_at`     | datetime | Investigation start time                 |
| `completed_at`   | datetime | Investigation completion time            |

**`harvested_wallets`** — Extracted crypto wallet addresses:

| Column              | Type     | Description                          |
| ------------------- | -------- | ------------------------------------ |
| `wallet_id` (PK)    | UUID     | Unique wallet record                 |
| `case_id` (FK)      | UUID     | Link to case                         |
| `scan_id` (FK)      | UUID     | Link to scan                         |
| `token_symbol`      | str      | BTC, ETH, USDT, etc.                 |
| `network_short`     | str      | btc, eth, trx, bsc, etc.             |
| `wallet_address`    | str      | The address                          |
| `source_label`      | str      | Raw label from site                  |
| `extraction_method` | enum     | js_regex \| llm_verified \| playbook |
| `confidence`        | float    | 0.0–1.0                              |
| `harvested_at`      | datetime | Extraction timestamp                 |

**`agent_sessions`** — Per-action audit trail:

| Column            | Type     | Description                              |
| ----------------- | -------- | ---------------------------------------- |
| `session_id` (PK) | UUID     | Unique action record                     |
| `scan_id` (FK)    | UUID     | Link to scan                             |
| `state`           | str      | Current FSM state                        |
| `action_type`     | enum     | click \| type \| select \| scroll \| ... |
| `selector`        | str      | CSS selector or text description         |
| `value`           | str      | Input value                              |
| `reasoning`       | str      | LLM's explanation                        |
| `confidence`      | float    | 0.0–1.0                                  |
| `strategy_used`   | str      | css \| text \| fuzzy \| dom_direct       |
| `screenshot_path` | str      | Path to screenshot                       |
| `timestamp`       | datetime | Action timestamp                         |

**`pii_exposures`** — What PII the scam site collects:

| Column             | Type | Description                                 |
| ------------------ | ---- | ------------------------------------------- |
| `exposure_id` (PK) | UUID | Unique exposure record                      |
| `scan_id` (FK)     | UUID | Link to scan                                |
| `field_label`      | str  | e.g., "Social Security Number"              |
| `field_type`       | enum | ssn \| credit_card \| email \| phone \| ... |
| `collection_step`  | str  | Which agent step captured this              |
| `form_action_url`  | str  | Where the form submits to                   |
| `is_required`      | bool | Whether the field is required               |

### 4.3 Evidence Storage Layout

```
data/evidence/{case_id}/
  ├── investigation.json         # Full structured result
  ├── report.md                  # Human-readable report
  ├── report.pdf                 # PDF version (with embedded evidence appendices)
  ├── leo_evidence_report.md     # Law enforcement summary
  ├── stix_bundle.json           # STIX 2.1 IOC bundle
  ├── wallet_manifest.json       # All extracted wallet addresses
  ├── evidence.zip               # All artifacts + SHA-256 manifest
  ├── passive/
  │   ├── screenshot.png         # Full-page screenshot
  │   ├── dom.html               # DOM snapshot
  │   ├── network.har            # HAR recording
  │   ├── ssl_cert.json          # SSL certificate details
  │   ├── whois.json             # WHOIS/RDAP record
  │   ├── dns.json               # DNS records
  │   └── geoip.json             # IP geolocation
  └── active/
      ├── session_log.json       # Agent action-by-action log
      ├── screenshots/           # Per-state screenshots
      └── wallets/
          └── extraction_detail.json
```

---

## 5. API Design

### 5.1 Endpoints

```
# Investigation lifecycle
POST   /investigate                    # Submit URL for investigation
POST   /investigate/batch              # Submit batch of URLs
GET    /investigate/{id}               # Poll investigation status
GET    /investigate/{id}/wallets       # Get extracted wallets
DELETE /investigate/{id}               # Cancel a running investigation

# Reports & evidence
GET    /report/{id}/pdf                # Download PDF report
GET    /report/{id}/evidence           # Download evidence ZIP
GET    /report/{id}/stix              # Download STIX bundle
GET    /report/{id}/wallets.xlsx       # Download wallet manifest as XLSX

# Real-time monitoring (WebSocket)
WS     /ws/monitor/{id}               # Events: state_change, screenshot, action,
                                       #         guidance_needed, wallet_found, complete
WS     /ws/guidance/{id}              # Commands: click, type, goto, skip, continue

# Wallet intelligence
GET    /wallets                        # Search across all harvested wallets
GET    /wallets/{address}              # Lookup a specific wallet address
GET    /wallets/stats                  # Aggregated stats (top tokens, networks)

# Playbook management
GET    /playbooks                      # List registered playbooks
POST   /playbooks                      # Create a new playbook
GET    /playbooks/{id}                 # Get playbook details
PUT    /playbooks/{id}                 # Update a playbook
DELETE /playbooks/{id}                 # Delete a playbook

# Health
GET    /health                         # Service health check
```

### 5.2 Request/Response Models

```python
class InvestigateRequest(BaseModel):
    url: str                           # Target URL (required)
    scan_type: ScanType = "full"       # passive | active | full
    playbook_id: str | None = None     # Force a specific playbook
    enable_wallet_extraction: bool = True
    enable_classification: bool = True
    enable_evidence_package: bool = True
    callback_url: str | None = None    # Webhook on completion
    priority: int = 0
    notes: str = ""

class InvestigationStatus(BaseModel):
    investigation_id: str
    case_id: str                       # Core case ID
    url: str
    status: str                        # queued | passive_recon | active_interaction |
                                       # classifying | packaging | completed | failed
    current_state: str | None          # FSM state (e.g., FILL_REGISTER)
    progress_pct: int                  # 0–100
    wallets_found: int
    risk_score: float | None
    classification: str | None
    started_at: datetime | None
    completed_at: datetime | None
    cost_usd: float
    error_message: str | None
```

---

## 6. Investigation Pipeline Detail

### 6.1 Orchestrator Flow

```python
async def investigate(url: str, scan_type: ScanType) -> InvestigationResult:
    """Three-phase investigation pipeline."""
    case = await create_case(url, source_type="ssi_scan")
    scan = await create_site_scan(case.case_id, scan_type)

    # Phase 1: Passive Recon (always runs)
    if scan_type in ("passive", "full"):
        passive = await run_passive_recon(url)
        await store_passive_results(scan, passive)
        await store_entities(case, passive)
        await store_indicators(case, passive)

    # Phase 2: Active Interaction (if requested)
    if scan_type in ("active", "full"):
        playbook = playbook_matcher.match(url)
        if playbook:
            active = await run_playbook(url, playbook, fallback=run_agent)
        else:
            active = await run_agent(url)
        await store_active_results(scan, active)
        await store_wallets(case, scan, active.wallets)
        await store_agent_session(scan, active.session_log)
        await store_pii_exposures(scan, active.pii_map)

    # Phase 3: Intelligence Synthesis (always runs)
    classification = await classify(case, passive, active)
    await update_case_classification(case, classification)
    evidence = await package_evidence(case, passive, active, classification)
    report = await generate_report(case, passive, active, classification)
    return InvestigationResult(case=case, scan=scan, evidence=evidence, report=report)
```

### 6.2 Active Interaction State Machine

```
                    ┌─────────────┐
                    │    INIT     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  LOAD_SITE  │ ← Navigate, dismiss overlays, screenshot
                    └──────┬──────┘
                           │
                    ┌──────▼──────────┐
                    │  FIND_REGISTER  │ ← DOM Inspector (≥75 direct, ≥40 assisted)
                    └──────┬──────────┘  ← LLM fallback if <40
                           │
                    ┌──────▼──────────┐
                    │  FILL_REGISTER  │ ← Generate identity, batch fill via LLM
                    └──────┬──────────┘  ← 4-tier type strategies + verification
                           │
                    ┌──────▼───────────┐
                    │ SUBMIT_REGISTER  │ ← Click submit, check for errors
                    └──────┬───────────┘  ← Opportunistic wallet scan
                           │
                    ┌──────▼──────────────────┐
                    │ CHECK_EMAIL_VERIFICATION│ ← DOM-only (zero LLM calls)
                    └──────┬──────────────────┘
                           │
               ┌───────────┼───────────────┐
               │ email required            │ no email needed
               ▼                           ▼
        ┌──────────┐              ┌────────────────┐
        │ SKIPPED  │              │NAVIGATE_DEPOSIT│ ← DOM Inspector + LLM
        └──────────┘              └───────┬────────┘
                                          │
                                  ┌───────▼────────┐
                                  │EXTRACT_WALLETS │ ← JS regex + coin tab discovery
                                  └───────┬────────┘  ← LLM verification
                                          │
                                  ┌───────▼────────┐
                                  │   COMPLETE     │
                                  └────────────────┘
```

At any state, stuck detection triggers → `GUIDANCE_NEEDED` → human intervention via WebSocket.

### 6.3 Four-Tier Decision Cascade

Each interaction step uses the cheapest strategy that can resolve the current state:

```
Step needed (e.g., "find the Register button")
  │
  ├─ Tier 1: Playbook ($0)
  │   Known site template? → Execute deterministic step
  │
  ├─ Tier 2: DOM Inspector ($0)
  │   Three-tier confidence scoring:
  │   • ≥75 confidence → direct action (no LLM)
  │   • ≥40 confidence → assisted (narrow candidates for LLM)
  │   • <40 → fall through to Tier 3
  │
  ├─ Tier 3: Gemini Flash text (~$0.0001/step)
  │   DOM extraction → numbered elements → LLM picks action
  │
  ├─ Tier 4: Gemini Flash vision (~$0.0002/step)
  │   Screenshot → LLM analyzes visual layout → action
  │   For: overlays, dynamic UIs, canvas content, error states
  │
  └─ Fallback: Human guidance ($0)
      WebSocket notification → analyst intervenes
```

**Cost target: <$0.01 per full investigation.**

### 6.4 LLM Provider Abstraction

```python
class LLMProvider(ABC):
    @abstractmethod
    async def analyze_page(self, screenshot, page_text, context, system_prompt) -> AgentAction: ...
    @abstractmethod
    async def classify(self, investigation_data, taxonomy_prompt) -> ClassificationResult: ...
    @abstractmethod
    async def batch_fill(self, screenshot, form_context, identity) -> list[AgentAction]: ...

class OllamaProvider(LLMProvider):     # Local: Llama 3.3 (text), Gemma 3 / Qwen3-VL (vision)
class GeminiProvider(LLMProvider):     # GCP: Gemini 2.0 Flash (primary), 2.5 Pro (escalation)
class MockProvider(LLMProvider):       # Testing
```

### 6.5 Playbook Execution Engine

Playbooks are JSON files matched by URL regex pattern. They enable deterministic scripted flows for known scam site templates, eliminating LLM costs entirely.

```python
class PlaybookExecutor:
    async def execute(self, url, playbook, browser, identity, fallback_agent=None):
        """Execute playbook steps sequentially.
        For each step: resolve template variables → execute action → verify → on failure: retry or fallback to LLM.
        """
```

### 6.6 Browser Automation Strategies

**Click strategies (4 tiers with fuzzy fallback):**

1. CSS `querySelector` → JS `.click()`
2. Text extraction → JS text search across buttons/links
3. zendriver's `find()` (text/label matching)
4. Fuzzy matching: keyword extraction from selectors → score all visible interactive elements

**Type strategies (4 tiers with verification):**

1. CSS `query_selector` → zendriver Element → clear → `send_keys` → fire events → readback verify
2. zendriver `find` → same typing path
3. JS-only fallback: React-compatible native property setter + synthetic events
4. Fuzzy find: keyword extraction + scoring, then native setter

Every type action reads back the field value after typing and verifies correctness.

**Additional strategies:**

- Overlay dismissal: auto-removes cookie banners, chat widgets (Intercom, Crisp, Drift, Tawk), Google Translate
- Screenshot optimization: CSS zoom 0.75, downscale 1920→1280, MD5 dedup, text-only mode for simple states
- Opportunistic wallet capture: JS probe during state transitions
- Batch fill: single LLM call to generate all form-fill actions (reduces N calls to 2)

---

## 7. Configuration

Settings follow a layered precedence model (highest wins):

1. CLI flags
2. Environment variables (`SSI_*` with `__` for nesting)
3. `config/settings.local.toml` (gitignored)
4. `config/settings.{env}.toml`
5. `config/settings.default.toml`

### 7.1 Key Configuration Sections

```toml
[llm]
provider = "ollama"                    # ollama | gemini | mock
model = "llama3.3"
model_vision = "gemma3:12b"
model_cheap = ""                       # Cheaper model for routine states
model_escalation = ""                  # Gemini 2.5 Pro (cloud only)
max_tokens = 1024
vision_enabled = true
prompt_cache_enabled = true

[browser]
headless = true
engine = "zendriver"
page_load_timeout = 45
action_timeout = 15
page_zoom = 0.75

[browser.dom_inspector]
enabled = true
direct_threshold = 75
assisted_threshold = 40

[wallet]
extraction_enabled = true
allowed_token_networks = "config/wallet_allowlist.json"

[agent]
max_actions_per_site = 80
stuck_thresholds = {FIND_REGISTER = 8, FILL_REGISTER = 15, ...}
max_repeated_actions = 3
enable_batch_fill = true
enable_opportunistic_wallet_scan = true

[playbook]
enabled = true
playbook_dir = "config/playbooks"

[monitoring]
websocket_enabled = true
screenshot_broadcast = true

[cost]
budget_per_investigation_usd = 1.0

[api]
host = "0.0.0.0"
port = 8100
max_concurrent_investigations = 5
```

See the [Configuration page](../../docs/book/ssi/configuration.md) for a complete environment variable reference.

---

## 8. UI Design

### 8.1 Page Structure

```
/ssi                          ← Investigation page (authenticated, quick scan toggle)
/ssi/investigations           ← Investigation list/history
/ssi/investigations/{id}      ← Investigation detail (3-tab view)
/ssi/wallets                  ← Wallet search/browse
```

### 8.2 Investigation Detail (3-Tab View)

```
┌─────────────────────────────────────────────────────────────┐
│ Investigation: https://scam-example.com                     │
│ Status: ● Active Interaction (FILL_REGISTER)    Cost: $0.12 │
├─────────────┬──────────────────┬────────────────────────────┤
│  Recon      │  Live Monitor    │  Results                   │
├─────────────┴──────────────────┴────────────────────────────┤
│                                                             │
│  [Tab: Recon]                                               │
│  WHOIS / DNS / SSL / GeoIP info cards                       │
│                                                             │
│  [Tab: Live Monitor]                                        │
│  Live screenshot + Action log + Guidance interface          │
│                                                             │
│  [Tab: Results]                                             │
│  Risk score + wallets table + PII exposure + evidence DL    │
└─────────────────────────────────────────────────────────────┘
```

### 8.3 WebSocket Communication

```typescript
interface MonitorEvent {
  type:
    | "state_change"
    | "screenshot"
    | "action"
    | "guidance_needed"
    | "wallet_found"
    | "progress"
    | "complete"
    | "error";
  investigation_id: string;
  timestamp: string;
  data:
    | StateChangeData
    | ScreenshotData
    | ActionData
    | GuidanceData
    | WalletData;
}

interface GuidanceCommand {
  type: "click" | "type" | "goto" | "skip" | "continue";
  value?: string;
  reason?: string;
}
```

---

## 9. Deployment Architecture

### 9.1 GCP Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        GCP Project (i4g-dev)                │
│                                                             │
│  ┌───────────────────┐     ┌──────────────────────────┐     │
│  │ Cloud Run Service │     │ Cloud Run Job            │     │
│  │ core gateway      │     │ ssi-investigate          │     │
│  │ (FastAPI, 19 rtr) │────▶│ (Browser + LLM + OSINT)  │     │
│  └────────┬──────────┘     └────────────┬─────────────┘     │
│           │                             │                   │
│  ┌────────▼─────────────────────────────▼────────────────┐  │
│  │                   VPC Network                         │  │
│  │  ┌────────────┐  ┌─────────────┐  ┌───────────────┐   │  │
│  │  │ Cloud SQL  │  │ GCS Bucket  │  │ Secret Manager│   │  │
│  │  │ (Postgres) │  │ (evidence)  │  │ (API keys)    │   │  │
│  │  └────────────┘  └─────────────┘  └───────────────┘   │  │
│  │  ┌────────────────┐  ┌─────────────────────────┐      │  │
│  │  │ Vertex AI      │  │ Artifact Registry       │      │  │
│  │  │ (Gemini API)   │  │ (Docker images)         │      │  │
│  │  └────────────────┘  └─────────────────────────┘      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ IAP (Identity-Aware Proxy) — protects core gateway     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 9.2 Terraform Resources

In `infra/environments/app/dev/`:

- `ssi_cloud_run_job.tf` — SSI investigation Cloud Run job
- `ssi_gcs.tf` — Evidence GCS bucket
- `ssi_secrets.tf` — OSINT API keys, proxy credentials
- `ssi_iam.tf` — `sa-ssi` service account + roles

SSI API endpoints are served by the core gateway Cloud Run Service (no separate SSI service).

### 9.3 Docker Images

```
docker/ssi-job.Dockerfile      → Chromium + zendriver + Playwright + OSINT + WeasyPrint
```

The SSI API is served by the core gateway image (`core/docker/fastapi.Dockerfile`).

---

## 10. Security

| Concern                           | Mitigation                                                                         |
| --------------------------------- | ---------------------------------------------------------------------------------- |
| Running untrusted code in browser | gVisor sandbox on Cloud Run, Chromium sandboxing                                   |
| PII exposure                      | Identity Vault uses invalid SSN ranges, test credit cards, controlled email domain |
| Scam site retaliation             | Residential proxy rotation, fingerprint randomization                              |
| Evidence integrity                | SHA-256 chain-of-custody manifest in every evidence ZIP                            |
| API access control                | IAP on Cloud Run, API key for service-to-service                                   |
| Sensitive OSINT keys              | GCP Secret Manager, never in code/config                                           |
| Legal (CFAA/CMA)                  | Automated interaction with scam sites requires legal review                        |
| Error sanitisation                | API errors return generic messages; full details logged server-side only           |
| Log safety                        | `type(e).__name__` in logs instead of `str(e)` to avoid leaking secrets            |

---

## 11. Hardening & Resilience

### Cost Budget Enforcement

`CostTracker` tracks per-investigation costs (LLM tokens, OSINT API calls, compute seconds). `check_budget()` raises `BudgetExceededError` between pipeline phases. All data collected before the budget trip is preserved.

Config: `SSI_COST__BUDGET_PER_INVESTIGATION_USD` (default: `1.0`).

### Concurrent Investigation Limit

Thread-safe counter in the routes layer. HTTP 429 when at capacity. Counter is decremented in `finally` block.

Config: `SSI_API__MAX_CONCURRENT_INVESTIGATIONS` (default: `5`).

### LLM Retry with Backoff

`RetryingLLMProvider` wraps any `LLMProvider` with exponential-backoff retry for transient errors (`ConnectionError`, `TimeoutError`, HTTP 429/5xx). Wired automatically by the factory.

### OSINT Retry Decorator

`ssi.osint.with_retries` is a shared decorator applied to all 6 OSINT modules. Retries on transient errors with configurable backoff.

### Error Handling

| Mechanism                  | Behavior                                               |
| -------------------------- | ------------------------------------------------------ |
| Blank page detection       | Progressive backoff (2–5s), per-state retry limits     |
| Screenshot dedup           | MD5 hash, 5 consecutive dupes → force stuck            |
| Repeated action detection  | 3 identical actions → force stuck                      |
| Scroll loop detection      | 2 unchanged positions → inject warning to LLM          |
| Type verification          | Readback + mismatch injection into LLM context         |
| Global safety limit        | 80 actions/site max → NEEDS_MANUAL_REVIEW              |
| Per-state stuck thresholds | Configurable (e.g., EXTRACT_WALLETS=20, CHECK_EMAIL=3) |

---

## 12. Testing Strategy

| Level           | Scope                                                                 | Tools                         |
| --------------- | --------------------------------------------------------------------- | ----------------------------- |
| **Unit**        | Models, DOM Inspector, wallet regex, playbook matcher, identity vault | pytest                        |
| **Integration** | LLM provider calls, DB operations, evidence packaging                 | pytest + fixtures             |
| **Browser**     | Page capture, form fill, wallet extraction (against test sites)       | pytest + zendriver/Playwright |
| **API**         | Endpoint contracts, WebSocket events                                  | pytest + httpx + websockets   |
| **E2E**         | Full investigation pipeline (against controlled test scam sites)      | pytest + Docker Compose       |

### Test Fixtures

Controlled test scam sites (static HTML files served locally) for repeatable browser testing:

```
tests/fixtures/scam_sites/
  ├── register.html            # Basic form + deposit page
  ├── deposit.html             # Wallet display patterns
  ├── phishing.html            # Phishing flow
  └── ...
```

**Current coverage**: 599 tests (575 unit + 24 integration).
