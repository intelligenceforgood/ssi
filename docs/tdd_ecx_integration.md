# SSI–eCrimeX Integration: Technical Design Document

> **Audience:** Developers and system architects
> **Last Updated**: March 5, 2026
> **Last Verified**: March 2026
> **Status**: Draft — Design Review
> **Parent Document**: `ssi/docs/tdd.md` (SSI TDD)
> **Product Requirements**: `planning/prd_ecx_integration.md`

This document is the technical design reference for integrating SSI with the APWG eCrimeX (eCX) data clearinghouse. It covers architecture, data models, API client design, configuration, phased implementation, and testing.

---

## 1. System Overview

### 1.1 Integration Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        SSI Investigation Pipeline                    │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Phase 1: Passive Recon                                         │  │
│  │  WHOIS │ DNS │ SSL │ GeoIP │ VirusTotal │ urlscan.io           │  │
│  │  ★ eCrimeX Enrichment (NEW)                                    │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │                                              │
│  ┌────────────────────▼───────────────────────────────────────────┐  │
│  │ Phase 2: Active Interaction                                    │  │
│  │  Browser agent → wallet extraction                             │  │
│  │  ★ Post-extraction eCX wallet lookup (NEW)                     │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │                                              │
│  ┌────────────────────▼───────────────────────────────────────────┐  │
│  │ Phase 3: Intelligence Synthesis                                │  │
│  │  Classification + reporting + evidence packaging               │  │
│  │  ★ eCX community intelligence section in report (NEW)          │  │
│  │  ★ eCX submission queue (Phase 2) (NEW)                        │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
         │                                           ▲
         │ POST/PUT submissions (Phase 2)            │ GET/search queries (Phase 1)
         ▼                                           │
┌─────────────────────────────────────────────────────────────────────┐
│                      eCrimeX API (v1.1)                             │
│                                                                     │
│  ┌──────────┐ ┌─────────────────┐ ┌──────────────┐ ┌─────────────┐  │
│  │  phish   │ │ malicious-domain│ │ malicious-ip │ │ crypto-addr │  │
│  └──────────┘ └─────────────────┘ └──────────────┘ └─────────────┘  │
│  ┌──────────────────┐ ┌──────────────┐                              │
│  │ report-phishing  │ │malicious-sms │                              │
│  └──────────────────┘ └──────────────┘                              │
│                                                                     │
│  Sandbox: sandbox.ecx2.ecrimex.net/api/v1                           │
│  Production: ecrimex.net/api/v1                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Map

| Component               | Path                                     | Phase | Purpose                                        |
| ----------------------- | ---------------------------------------- | ----- | ---------------------------------------------- |
| `ECXClient`             | `ssi/src/ssi/osint/ecrimex.py`           | 1     | HTTP client for all eCX API interactions       |
| `ECXSettings`           | `ssi/src/ssi/settings/config.py`         | 1     | Pydantic settings model for `[ecx]` section    |
| `ecx_currency_map.json` | `ssi/config/ecx_currency_map.json`       | 1     | Token symbol → eCX currency code mapping       |
| `ECXEnrichmentResult`   | `ssi/src/ssi/models/ecx.py`              | 1     | Pydantic models for eCX enrichment data        |
| `ecx_submissions` table | Alembic migration                        | 2     | Tracks eCX submission lifecycle                |
| `ecx_enrichments` table | Alembic migration                        | 1     | Caches eCX query results per investigation     |
| Submission governance   | `ssi/src/ssi/services/ecx_submission.py` | 2     | Hybrid auto/manual submission logic            |
| Inbound poller          | `ssi/src/ssi/services/ecx_poller.py`     | 3     | Scheduled eCX polling + investigation triggers |
| CLI commands            | `ssi/src/ssi/cli/ecx.py`                 | 1     | `ssi ecx search`, `ssi ecx submit`, etc.       |

---

## 2. Architectural Decisions

### ADR-ECX-1: eCX Client as OSINT Module

**Choice**: Implement eCX integration as a new module in `ssi/src/ssi/osint/ecrimex.py`, following the pattern of `virustotal.py` and `urlscan.py`.

**Rationale**: eCX enrichment (Phase 1) is functionally identical to other OSINT sources — query an external API during passive recon, extract threat indicators. Using the existing OSINT module pattern means:

- Same retry/backoff (`@with_retries` decorator)
- Same graceful degradation (missing API key → skip, not crash)
- Same settings pattern (`SSI_ECX__*` env vars)
- Same integration point in the orchestrator pipeline

**Submission (Phase 2) extends beyond OSINT** — it is a post-investigation action, not a recon step. Submission logic lives in a separate service (`ecx_submission.py`) that consumes the client but is invoked after intelligence synthesis.

### ADR-ECX-2: Sandbox-First Development

**Choice**: Default `base_url` points to eCX sandbox (`sandbox.ecx2.ecrimex.net/api/v1`). Production URL is set via configuration.

**Rationale**: eCX provides a sandbox explicitly for development and testing. Using sandbox by default:

- Eliminates risk of polluting production eCX data during development
- Allows submission testing without a data sharing agreement
- Validates API integration before production cutover

**Switch to production**: Set `SSI_ECX__BASE_URL=https://ecrimex.net/api/v1`.

### ADR-ECX-3: Caching eCX Responses

**Choice**: Cache eCX enrichment results in a local `ecx_enrichments` table, keyed by (query_type, query_value, investigation_id).

**Rationale**:

- Avoids redundant API calls for repeated investigations of the same URL
- Preserves enrichment data even if eCX is temporarily unavailable during report generation
- Enables offline report regeneration
- Cache TTL is configurable (default: 24 hours) to balance freshness vs. API usage

### ADR-ECX-4: Currency Mapping Strategy

**Choice**: Configurable JSON mapping file (`ecx_currency_map.json`) rather than hardcoded enum translation.

**Rationale**: The eCX `currency` field is a closed enum (15 values). SSI's wallet allowlist has partial overlap. A mapping file:

- Decouples SSI token symbols from eCX's enum without code changes
- Allows instant updates when APWG adds currencies
- Can flag "unmapped" currencies for logging and future expansion
- Is consistent with SSI's existing `wallet_allowlist.json` configuration pattern

---

## 3. Data Models

### 3.1 Pydantic Models

```python
# ssi/src/ssi/models/ecx.py

class ECXPhishRecord(BaseModel):
    """A phish record from eCrimeX."""
    id: int
    url: str
    brand: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    created_at: int | None = None
    updated_at: int | None = None
    ip: list[str] = []
    asn: list[int] = []
    tld: str = ""
    metadata: dict[str, Any] = {}

class ECXCryptoRecord(BaseModel):
    """A cryptocurrency address record from eCrimeX."""
    id: int
    currency: str
    address: str
    crime_category: str = ""
    site_link: str = ""
    price: int = 0
    source: str = ""
    procedure: str = ""
    actor_category: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    metadata: dict[str, Any] = {}
    notes: list[dict[str, Any]] = []

class ECXMalDomainRecord(BaseModel):
    """A malicious domain record from eCrimeX."""
    id: int
    domain: str
    classification: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    metadata: dict[str, Any] = {}
    notes: list[dict[str, Any]] = []

class ECXMalIPRecord(BaseModel):
    """A malicious IP record from eCrimeX."""
    id: int
    ip: str = ""
    brand: str = ""
    description: str = ""
    confidence: int = 0
    status: str = ""
    asn: list[int] = []
    port: int | None = None
    discovered_at: int | None = None
    metadata: dict[str, Any] = {}

class ECXEnrichmentResult(BaseModel):
    """Aggregated eCX enrichment for a single investigation."""
    phish_hits: list[ECXPhishRecord] = []
    domain_hits: list[ECXMalDomainRecord] = []
    ip_hits: list[ECXMalIPRecord] = []
    crypto_hits: list[ECXCryptoRecord] = []
    report_phishing_hits: list[dict[str, Any]] = []
    query_count: int = 0
    total_hits: int = 0
    query_duration_ms: float = 0
    errors: list[str] = []

class ECXSubmissionRecord(BaseModel):
    """Tracks a submission to eCrimeX."""
    ecx_module: str
    ecx_record_id: int | None = None
    case_id: str
    scan_id: str
    submitted_value: str  # URL, address, domain, or IP
    confidence: int
    status: str  # pending | submitted | updated | failed | retracted
    release_label: str = ""
    submitted_by: str = ""  # analyst username or "auto"
    submitted_at: datetime | None = None
    error_message: str = ""
```

### 3.2 Database Schema

#### `ecx_enrichments` — Cache Layer (Phase 1)

| Column               | Type     | Description                                                     |
| -------------------- | -------- | --------------------------------------------------------------- |
| `enrichment_id` (PK) | UUID     | Unique enrichment record                                        |
| `scan_id` (FK)       | UUID     | Link to `site_scans`                                            |
| `query_module`       | str      | phish, malicious-domain, malicious-ip, cryptocurrency-addresses |
| `query_value`        | str      | The URL, domain, IP, or address queried                         |
| `ecx_record_id`      | int      | eCX record ID of the hit                                        |
| `ecx_data`           | JSONB    | Full eCX response record                                        |
| `confidence`         | int      | eCX confidence value                                            |
| `queried_at`         | datetime | When the query was made                                         |
| `cache_expires_at`   | datetime | TTL expiry                                                      |

#### `ecx_submissions` — Submission Tracker (Phase 2)

| Column               | Type     | Description                                                     |
| -------------------- | -------- | --------------------------------------------------------------- |
| `submission_id` (PK) | UUID     | Unique submission record                                        |
| `case_id` (FK)       | UUID     | Link to case                                                    |
| `scan_id` (FK)       | UUID     | Link to scan                                                    |
| `ecx_module`         | str      | phish, malicious-domain, malicious-ip, cryptocurrency-addresses |
| `ecx_record_id`      | int      | eCX record ID (returned on successful submit)                   |
| `submitted_value`    | str      | URL, domain, IP, or wallet address                              |
| `confidence`         | int      | Confidence value submitted                                      |
| `release_label`      | str      | Analyst-assigned label                                          |
| `status`             | enum     | pending, submitted, updated, failed, retracted                  |
| `submitted_by`       | str      | "auto" or analyst username                                      |
| `submitted_at`       | datetime | Submission timestamp                                            |
| `error_message`      | str      | Error details if failed                                         |
| `created_at`         | datetime | Record creation time                                            |

---

## 4. eCX API Client

### 4.1 Client Design

```python
# ssi/src/ssi/osint/ecrimex.py

class ECXClient:
    """HTTP client for the eCrimeX API v1.1.

    Handles authentication, request/response mapping, retries, and
    rate limiting for all six eCX modules.

    Args:
        base_url: eCX API base URL.
        api_key: Bearer token for authentication.
        attribution: Organization name for submissions.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        attribution: str = "IntelligenceForGood",
        timeout: int = 15,
    ) -> None: ...

    # --- Phase 1: Query / Enrichment ---

    def search_phish(self, url: str, limit: int = 10) -> list[ECXPhishRecord]:
        """Search for phishing records matching a URL."""
        ...

    def search_domain(self, domain: str, limit: int = 10) -> list[ECXMalDomainRecord]:
        """Search for malicious domain records."""
        ...

    def search_ip(self, ip: str, limit: int = 10) -> list[ECXMalIPRecord]:
        """Search for malicious IP records."""
        ...

    def search_crypto(self, address: str, limit: int = 10) -> list[ECXCryptoRecord]:
        """Search for cryptocurrency address records."""
        ...

    def search_report_phishing(self, url: str, limit: int = 10) -> list[dict[str, Any]]:
        """Search reportphishing email archive for a URL."""
        ...

    # --- Phase 2: Submit / Update ---

    def submit_phish(
        self,
        url: str,
        confidence: int = 90,
        brand: str = "",
        ip: list[str] | None = None,
    ) -> int:
        """Submit a phishing URL. Returns the eCX record ID."""
        ...

    def submit_crypto(
        self,
        address: str,
        currency: str,
        confidence: int = 90,
        crime_category: str = "scam",
        site_link: str = "",
        procedure: str = "automatic",
    ) -> int:
        """Submit a cryptocurrency address. Returns the eCX record ID."""
        ...

    def submit_domain(
        self,
        domain: str,
        classification: str = "scam",
        confidence: int = 90,
    ) -> int:
        """Submit a malicious domain. Returns the eCX record ID."""
        ...

    def submit_ip(
        self,
        ip: str,
        confidence: int = 90,
        description: str = "",
    ) -> int:
        """Submit a malicious IP. Returns the eCX record ID."""
        ...

    def add_note(self, module: str, record_id: int, description: str) -> int:
        """Add a note to a malicious-domain or cryptocurrency-addresses record."""
        ...

    def update_record(self, module: str, record_id: int, confidence: int, status: str) -> None:
        """Update confidence or status on an existing record."""
        ...
```

### 4.2 Authentication

```python
def _headers(self) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {self._api_key}",
        "Content-Type": "application/json",
    }
```

eCX uses HTTP Bearer token authentication. The API key is stored in `SSI_ECX__API_KEY` (env var) or Secret Manager (GCP).

### 4.3 Error Handling & Resilience

The client follows the established SSI OSINT pattern:

| Scenario                | Behavior                                                     |
| ----------------------- | ------------------------------------------------------------ |
| API key not configured  | Log info, return empty results (graceful skip)               |
| Module access denied    | Log warning with module name, return empty results, continue |
| HTTP 429 (rate limit)   | Exponential backoff retry (max 3 attempts)                   |
| HTTP 5xx (server error) | Retry with backoff                                           |
| HTTP 4xx (client error) | Log error, do not retry                                      |
| Network timeout         | Retry with backoff                                           |
| eCX fully unreachable   | Log warning, investigation continues without eCX enrichment  |

```python
@with_retries(
    max_retries=3,
    backoff_seconds=2.0,
    retryable_exceptions=(httpx.TransportError, httpx.HTTPStatusError),
    retryable_status_codes=(429, 500, 502, 503, 504),
)
def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
    """Execute an HTTP request with retry and rate-limit handling."""
    ...
```

### 4.4 Search Implementation

eCX search uses POST with a structured body. The client translates SSI query patterns to eCX's filter format:

```python
def search_phish(self, url: str, limit: int = 10) -> list[ECXPhishRecord]:
    """Search phish records by URL substring match."""
    body = {
        "filters": {"url": url},
        "fields": ["id", "url", "brand", "confidence", "status",
                    "discoveredAt", "ip", "asn", "tld", "createdAt"],
        "limit": limit,
    }
    resp = self._request("POST", "/phish/search", json=body)
    data = resp.json().get("data", [])
    return [ECXPhishRecord(**self._normalize_keys(r)) for r in data]
```

### 4.5 Key Normalization

eCX returns `camelCase` keys (`discoveredAt`, `createdAt`). SSI models use `snake_case`. The client normalizes:

```python
_FIELD_MAP = {
    "discoveredAt": "discovered_at",
    "createdAt": "created_at",
    "updatedAt": "updated_at",
    "submissionCount": "submission_count",
    "crimeCategory": "crime_category",
    "siteLink": "site_link",
    "actorCategory": "actor_category",
}

def _normalize_keys(self, record: dict[str, Any]) -> dict[str, Any]:
    """Convert eCX camelCase keys to snake_case."""
    return {self._FIELD_MAP.get(k, k): v for k, v in record.items()}
```

---

## 5. Integration into Investigation Pipeline

### 5.1 Enrichment Hook (Phase 1)

The eCX enrichment runs as part of passive recon, alongside existing OSINT queries:

```python
# In orchestrator.py — Phase 1: Passive Recon
async def run_passive_recon(url: str) -> PassiveReconResult:
    # ... existing OSINT calls ...
    whois = lookup_whois(url)
    dns = lookup_dns(url)
    ssl = check_ssl(url)
    geoip = lookup_geoip(primary_ip)
    vt = check_url(url)           # VirusTotal
    urlscan = scan_url(url)       # urlscan.io

    # ★ NEW: eCrimeX enrichment
    ecx = enrich_from_ecx(url, domain, primary_ip)

    return PassiveReconResult(..., ecx_enrichment=ecx)
```

The `enrich_from_ecx` function is the top-level orchestrator for all eCX queries:

```python
# ssi/src/ssi/osint/ecrimex.py

def enrich_from_ecx(
    url: str,
    domain: str,
    ip: str | None = None,
) -> ECXEnrichmentResult:
    """Query eCrimeX for enrichment data across all accessible modules.

    Queries are parallelized where possible and individually fault-tolerant.
    A failure in one module does not block others.

    Args:
        url: The target URL being investigated.
        domain: Extracted domain from the URL.
        ip: Primary hosting IP (if resolved).

    Returns:
        Aggregated enrichment result.
    """
    settings = get_settings()
    if not settings.ecx.enabled or not settings.ecx.enrichment_enabled:
        return ECXEnrichmentResult()

    client = _get_client()
    result = ECXEnrichmentResult()
    start = time.monotonic()

    # Query each module independently — failures are isolated
    result.phish_hits = _safe_query(client.search_phish, url, result.errors)
    result.domain_hits = _safe_query(client.search_domain, domain, result.errors)
    if ip:
        result.ip_hits = _safe_query(client.search_ip, ip, result.errors)
    result.report_phishing_hits = _safe_query(
        client.search_report_phishing, url, result.errors
    )

    result.query_count = 3 + (1 if ip else 0)
    result.total_hits = (
        len(result.phish_hits) + len(result.domain_hits)
        + len(result.ip_hits) + len(result.report_phishing_hits)
    )
    result.query_duration_ms = (time.monotonic() - start) * 1000

    return result
```

### 5.2 Wallet Enrichment (Phase 1, Post-Extraction)

After wallet extraction in Phase 2 (Active Interaction), each wallet address is cross-referenced against eCX:

```python
# After wallet extraction
async def enrich_wallets_from_ecx(
    wallets: list[HarvestedWallet],
) -> dict[str, list[ECXCryptoRecord]]:
    """Cross-reference extracted wallets against eCX cryptocurrency-addresses.

    Args:
        wallets: Wallets extracted by the browser agent.

    Returns:
        Dict mapping wallet address → list of eCX matches.
    """
    client = _get_client()
    hits: dict[str, list[ECXCryptoRecord]] = {}
    for wallet in wallets:
        records = _safe_query(client.search_crypto, wallet.wallet_address, [])
        if records:
            hits[wallet.wallet_address] = records
    return hits
```

### 5.3 Report Integration

The eCX enrichment result feeds into the investigation report as a new section:

```markdown
## Community Intelligence (eCrimeX)

### Phishing Records

- **3 prior submissions** found for this URL
  - eCX #112124609 — Brand: Rakuten, Confidence: 100, First seen: 2026-02-15
  - eCX #111998832 — Brand: Rakuten, Confidence: 90, First seen: 2026-02-10
  - eCX #111876543 — Brand: PayPal, Confidence: 50, First seen: 2026-01-28

### Malicious Domain

- **Domain classified as "scam"** in eCX (confidence: 100, 5 submissions)

### Cryptocurrency Addresses

- **Wallet 0x1a2b...** found in eCX:
  - Crime category: scam, Currency: ETH, 12 prior reports
  - Associated sites: fake-exchange.com, cryptoinvest-pro.xyz

### Malicious Infrastructure

- **Hosting IP 172.31.138.180** flagged in eCX:
  - Description: "Hosting multiple phishing campaigns"
  - ASN: 20940, Confidence: 100
```

### 5.4 STIX 2.1 Integration

eCX enrichment hits are included in the STIX bundle as external references:

```python
# Add eCX source attribution to STIX indicators
stix_indicator = stix2.Indicator(
    name=f"Phishing URL: {url}",
    pattern=f"[url:value = '{url}']",
    pattern_type="stix",
    external_references=[
        stix2.ExternalReference(
            source_name="eCrimeX (APWG)",
            external_id=str(ecx_record.id),
            description=f"eCX phish record, confidence={ecx_record.confidence}",
        )
    ],
)
```

---

## 6. Submission Service (Phase 2)

### 6.1 Governance Engine

```python
# ssi/src/ssi/services/ecx_submission.py

class ECXSubmissionService:
    """Manages the lifecycle of eCX submissions with hybrid governance.

    Implements the configurable threshold model:
    - risk_score >= threshold → auto-submit
    - risk_score >= 50 but < threshold → queue for analyst review
    - risk_score < 50 → do not submit (manual override available)
    """

    def __init__(self, client: ECXClient, store: ScanStore, settings: ECXSettings) -> None:
        self._client = client
        self._store = store
        self._settings = settings

    def process_investigation(
        self,
        case_id: str,
        scan_id: str,
        risk_score: float,
        investigation_result: InvestigationResult,
    ) -> list[ECXSubmissionRecord]:
        """Evaluate and process eCX submissions for a completed investigation.

        Returns list of submission records (submitted or queued).
        """
        if not self._settings.submission_enabled:
            return []

        records: list[ECXSubmissionRecord] = []

        if risk_score >= self._settings.auto_submit_threshold:
            records = self._auto_submit(case_id, scan_id, investigation_result)
        elif risk_score >= 50:
            records = self._queue_for_review(case_id, scan_id, investigation_result)
        # risk_score < 50: no action (analyst can manually override)

        return records

    def analyst_approve(
        self,
        submission_id: str,
        release_label: str,
        analyst: str,
    ) -> ECXSubmissionRecord:
        """Analyst approves a queued submission."""
        ...

    def analyst_reject(
        self,
        submission_id: str,
        analyst: str,
        reason: str = "",
    ) -> ECXSubmissionRecord:
        """Analyst rejects a queued submission."""
        ...

    def retract(self, submission_id: str, analyst: str) -> ECXSubmissionRecord:
        """Retract a previously submitted record (update status to inactive)."""
        ...
```

### 6.2 Submission Mapping

SSI investigation data maps to eCX submission fields as follows:

**Phish submission:**

| SSI Field                | eCX Field      | Mapping                                      |
| ------------------------ | -------------- | -------------------------------------------- |
| Target URL               | `url`          | Direct                                       |
| Classification brand     | `brand`        | SSI taxonomy → closest brand name            |
| Investigation risk_score | `confidence`   | ≥80 → 90 (automated), analyst-verified → 100 |
| Hosting IPs              | `ip`           | From passive recon                           |
| Investigation timestamp  | `discoveredAt` | Epoch seconds                                |
| —                        | `status`       | "active"                                     |

**Cryptocurrency submission:**

| SSI Field               | eCX Field       | Mapping                       |
| ----------------------- | --------------- | ----------------------------- |
| `wallet_address`        | `address`       | Direct                        |
| `token_symbol`          | `currency`      | Via `ecx_currency_map.json`   |
| Target URL              | `siteLink`      | Direct                        |
| Classification category | `crimeCategory` | Taxonomy mapping → eCX enum   |
| —                       | `procedure`     | "automatic"                   |
| —                       | `source`        | "web"                         |
| Investigation timestamp | `discoveredAt`  | Epoch seconds                 |
| `confidence`            | `confidence`    | Wallet confidence → eCX scale |

**Malicious domain submission:**

| SSI Field                | eCX Field        | Mapping                                                     |
| ------------------------ | ---------------- | ----------------------------------------------------------- |
| Extracted domain         | `domain`         | Direct                                                      |
| Classification           | `classification` | SSI taxonomy → eCX enum (scam, malicious, fake store, etc.) |
| Investigation risk_score | `confidence`     | Same as phish mapping                                       |

### 6.3 Deduplication Logic

Before each submission, check eCX for existing records:

```python
def _submit_with_dedup(
    self, module: str, search_fn, submit_fn, value: str, **submit_kwargs
) -> ECXSubmissionRecord:
    """Submit to eCX with deduplication.

    If the value already exists in eCX:
    - If our confidence is higher → update via PUT
    - Otherwise → add a note with SSI context
    If the value is new → submit via POST
    """
    existing = search_fn(value, limit=1)
    if existing:
        record = existing[0]
        if submit_kwargs.get("confidence", 0) > record.confidence:
            self._client.update_record(module, record.id, ...)
            return ECXSubmissionRecord(status="updated", ecx_record_id=record.id, ...)
        else:
            self._client.add_note(module, record.id, f"Corroborated by SSI investigation {case_id}")
            return ECXSubmissionRecord(status="updated", ecx_record_id=record.id, ...)
    else:
        ecx_id = submit_fn(**submit_kwargs)
        return ECXSubmissionRecord(status="submitted", ecx_record_id=ecx_id, ...)
```

---

## 7. Currency Mapping

### 7.1 Mapping File

```json
// ssi/config/ecx_currency_map.json
{
  "_comment": "Maps SSI token_symbol to eCX currency code. Unmapped tokens are logged and skipped.",
  "_version": "1.0.0",
  "mappings": {
    "ADA": "ADA",
    "BCH": "BCH",
    "BNB": "BNB",
    "BTC": "BTC",
    "DASH": "DASH",
    "DOGE": "DOGE",
    "ETH": "ETH",
    "LTC": "LTC",
    "TRX": "TRX",
    "XLM": "XLM",
    "XMR": "XMR",
    "XRP": "XRP",
    "XZC": "XZC",
    "ZEC": "ZEC"
  },
  "unmapped_action": "log_and_skip"
}
```

### 7.2 Wallet Allowlist Expansion

To close the gap between SSI extraction and eCX submission, expand the wallet allowlist with new regex patterns:

| Token | Network    | Address Pattern                        | Regex                                   |
| ----- | ---------- | -------------------------------------- | --------------------------------------- |
| XLM   | Stellar    | Starts with `G`, 56 chars, base32      | `^G[A-Z2-7]{55}$`                       |
| XMR   | Monero     | Starts with `4` or `8`, 95 chars       | `^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$` |
| XZC   | Zcoin/Firo | Starts with `a` or `Z`, 34 chars       | `^[aZ][a-km-zA-HJ-NP-Z1-9]{33}$`        |
| ZEC   | Zcash      | Starts with `t1` or `t3` (transparent) | `^t[13][a-km-zA-HJ-NP-Z1-9]{33}$`       |

These are added to `config/wallet_allowlist.json` and the corresponding JS regex patterns for browser-side extraction in the wallet extraction module.

---

## 8. Configuration

### 8.1 Settings Model

```python
# Addition to ssi/src/ssi/settings/config.py

class ECXSettings(BaseSettings):
    """eCrimeX integration configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_ECX__")

    enabled: bool = False
    api_key: str = ""
    base_url: str = "https://sandbox.ecx2.ecrimex.net/api/v1"
    attribution: str = "IntelligenceForGood"
    timeout_sec: int = 15

    # Phase 1: Enrichment
    enrichment_enabled: bool = True
    cache_ttl_hours: int = 24

    # Phase 2: Submission
    submission_enabled: bool = False
    auto_submit_threshold: int = 80
    submission_modules: list[str] = Field(
        default=["phish", "cryptocurrency-addresses", "malicious-domain"]
    )

    # Phase 3: Inbound polling
    inbound_enabled: bool = False
    inbound_poll_interval_min: int = 15
    inbound_modules: list[str] = Field(
        default=["phish", "report-phishing"]
    )

    # Currency mapping
    currency_map_path: str = "config/ecx_currency_map.json"
```

### 8.2 TOML Defaults

```toml
# Addition to config/settings.default.toml

[ecx]
enabled = false
base_url = "https://sandbox.ecx2.ecrimex.net/api/v1"
attribution = "IntelligenceForGood"
timeout_sec = 15

enrichment_enabled = true
cache_ttl_hours = 24

submission_enabled = false
auto_submit_threshold = 80
submission_modules = ["phish", "cryptocurrency-addresses", "malicious-domain"]

inbound_enabled = false
inbound_poll_interval_min = 15
inbound_modules = ["phish", "report-phishing"]

currency_map_path = "config/ecx_currency_map.json"
```

### 8.3 Secret Management

| Environment | Storage Mechanism                  |
| ----------- | ---------------------------------- |
| Local       | `SSI_ECX__API_KEY` in `.env.local` |
| Dev (GCP)   | Secret Manager: `ssi-ecx-api-key`  |
| Prod (GCP)  | Secret Manager: `ssi-ecx-api-key`  |

The API key must **never** appear in TOML config files, source code, or Terraform variables.

---

## 9. API Surface

### 9.1 New SSI API Endpoints

```
# eCX enrichment (read-only, available in Phase 1)
GET  /investigate/{id}/ecx          # Get eCX enrichment data for an investigation

# eCX submission management (Phase 2)
GET  /ecx/submissions               # List submission queue (filterable by status)
POST /ecx/submissions/{id}/approve  # Analyst approves a queued submission
POST /ecx/submissions/{id}/reject   # Analyst rejects a queued submission
POST /ecx/submissions/{id}/retract  # Retract a previously submitted record

# eCX search (ad-hoc, Phase 1)
POST /ecx/search/phish              # Search eCX phish records
POST /ecx/search/domain             # Search eCX malicious-domain records
POST /ecx/search/ip                 # Search eCX malicious-ip records
POST /ecx/search/crypto             # Search eCX cryptocurrency records
```

### 9.2 Request/Response Models

```python
class ECXApproveRequest(BaseModel):
    release_label: str       # Required — analyst must provide a label
    analyst: str = ""        # Auto-populated from auth context

class ECXSubmissionResponse(BaseModel):
    submission_id: str
    ecx_module: str
    ecx_record_id: int | None
    status: str              # pending | submitted | updated | failed | retracted
    submitted_value: str
    release_label: str
    submitted_at: datetime | None

class ECXSearchRequest(BaseModel):
    query: str               # URL, domain, IP, or wallet address
    limit: int = 10
```

---

## 10. CLI Commands

```
# Phase 1: Search
ssi ecx search phish <url>          # Search eCX for phishing records
ssi ecx search domain <domain>      # Search eCX for malicious domain records
ssi ecx search ip <ip>              # Search eCX for malicious IP records
ssi ecx search crypto <address>     # Search eCX for cryptocurrency address records

# Phase 2: Submission management
ssi ecx submit <investigation-id>   # Manually submit investigation to eCX
ssi ecx status <investigation-id>   # Check submission status for an investigation
ssi ecx retract <submission-id>     # Retract a submission

# Phase 3: Polling
ssi ecx poll                        # Manually trigger inbound polling
ssi ecx poll --module phish         # Poll a specific module
```

---

## 11. Inbound Poller (Phase 3)

### 11.1 Architecture

```python
# ssi/src/ssi/services/ecx_poller.py

class ECXPoller:
    """Scheduled poller that queries eCX for new submissions.

    Triggers SSI investigations for new phishing URLs and scam domains
    that match configurable criteria.
    """

    def __init__(
        self,
        client: ECXClient,
        settings: ECXSettings,
        investigation_trigger: Callable[[str], None],
    ) -> None: ...

    def poll_module(self, module: str) -> list[str]:
        """Poll a single eCX module for new records since last poll.

        Returns list of URLs/domains submitted for investigation.
        """
        ...

    def run_poll_cycle(self) -> dict[str, int]:
        """Execute one full polling cycle across all configured modules.

        Returns dict of {module: count_of_new_investigations_triggered}.
        """
        ...
```

### 11.2 Polling Strategy

- Track `last_polled_id` per module in the database
- Each cycle: query eCX with `filters: {"id": {"from": last_polled_id}}`, sorted ascending
- Filter results by configurable criteria (confidence threshold, brands, TLDs)
- Deduplicate against existing SSI investigations
- Submit qualifying URLs for SSI investigation via the standard pipeline
- Update `last_polled_id`

### 11.3 Deployment

On GCP, the poller runs as a Cloud Scheduler-triggered Cloud Run Job (same pattern as other SSI jobs). Locally, it runs as a Typer CLI command invoked via cron or manually.

#### Local Execution

```bash
# Run one full polling cycle manually
conda run -n i4g-ssi ssi ecx poll

# Poll only the phish module
conda run -n i4g-ssi ssi ecx poll --module phish
```

Required env vars for local polling:

- `SSI_ECX__ENABLED=true`
- `SSI_ECX__POLLING_ENABLED=true`
- `SSI_ECX__API_KEY=<key>`

#### GCP Deployment

The poller reuses the existing `ssi-svc` Docker image with the entrypoint args `["ecx", "poll"]`. Infrastructure is defined in `infra/environments/app/dev/terraform.tfvars` under the `ecx_poller` entry in `run_jobs`.

**Cloud Run Job:** `ssi-ecx-poller`

- Image: `us-central1-docker.pkg.dev/i4g-dev/applications/ssi-svc:dev`
- Service account: SSI service account (shared with the SSI API service)
- Timeout: 300 s, max retries: 1
- VPC connector: Serverless connector (for Cloud SQL access)

**Cloud Scheduler:** Triggers the job every 15 minutes (`*/15 * * * *`).

**Environment Variables** (set in `terraform.tfvars`):

| Variable                                | Value                            | Purpose                         |
| --------------------------------------- | -------------------------------- | ------------------------------- |
| `SSI_ECX__ENABLED`                      | `true`                           | Enable eCX integration          |
| `SSI_ECX__POLLING_ENABLED`              | `true`                           | Enable polling mode             |
| `SSI_ECX__POLLING_MODULES`              | `phish`                          | Modules to poll                 |
| `SSI_ECX__POLLING_CONFIDENCE_THRESHOLD` | `50`                             | Min confidence to act on        |
| `SSI_ECX__POLLING_AUTO_INVESTIGATE`     | `false`                          | Auto-trigger SSI investigations |
| `SSI_ECX__BASE_URL`                     | `https://api.ecrimex.net/api/v1` | eCX API base URL                |
| `SSI_LLM__PROVIDER`                     | `mock`                           | LLM provider for job context    |

**Secrets** (via Secret Manager):

| Variable           | Secret Reference                                  |
| ------------------ | ------------------------------------------------- |
| `SSI_ECX__API_KEY` | `projects/i4g-dev/secrets/ssi-ecx-api-key:latest` |

#### Monitoring

The poller tracks state in the `ecx_polling_state` table:

- `last_polled_id` — cursor for incremental polling per module
- `records_found` / `errors` — counters from the last cycle
- `last_polled_at` — timestamp of last successful poll

Query polling health:

```bash
conda run -n i4g-ssi ssi ecx poll-status
```

### 11.4 Campaign Correlation

The `CampaignCorrelator` (in `ssi/src/ssi/ecx/correlation.py`) links related SSI investigations into campaigns using three strategies:

1. **Wallet-based** — Investigations sharing the same cryptocurrency wallet address are grouped into a campaign with taxonomy label `shared-wallet`.
2. **Infrastructure-based** — Investigations sharing hosting IP addresses (from eCX phish or malicious-ip enrichments) are grouped with taxonomy label `shared-infrastructure`.
3. **Brand-based** — Investigations impersonating the same brand within a configurable time window (default 30 days) are grouped with taxonomy label `brand-impersonation`.

Each strategy creates a record in core's `campaigns` table and links matching cases via `cases.campaign_id`. Deduplication ensures cases already in a campaign are not reassigned.

```python
from ssi.ecx.correlation import get_correlator

correlator = get_correlator()
if correlator:
    results = correlator.correlate_all()
    # {"wallet": 3, "infrastructure": 1, "brand": 2}
```

---

## 12. Security

| Concern                          | Mitigation                                                                                                                                  |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| API key exposure                 | Secret Manager (GCP) or `.env.local` (local). Never in source or config files.                                                              |
| Data leakage to eCX              | Only infrastructure indicators submitted (URLs, domains, IPs, wallets). No PII. No synthetic identity data.                                 |
| eCX data integrity               | All eCX responses validated through Pydantic models before use.                                                                             |
| Submission attribution           | Configurable attribution string. No analyst PII shared with eCX.                                                                            |
| Rate limiting                    | Client-side rate limiting to stay within eCX quotas.                                                                                        |
| Sandbox vs. production isolation | Environment-specific `base_url`. Submission to production requires explicit `submission_enabled=true` + production URL. Default is sandbox. |
| Audit trail                      | Every eCX query and submission logged with timestamp, module, user, and response.                                                           |

---

## 13. Testing Strategy

### 13.1 Unit Tests

| Area                   | Coverage                                                                          |
| ---------------------- | --------------------------------------------------------------------------------- |
| `ECXClient`            | Mock HTTP responses, validate request construction, field mapping, error handling |
| `ECXEnrichmentResult`  | Model validation, aggregation logic                                               |
| `ECXSubmissionService` | Governance thresholds, dedup logic, approval/rejection flows                      |
| Currency mapping       | Load `ecx_currency_map.json`, mapped/unmapped handling                            |
| Settings               | Environment variable overrides for all `ECXSettings` fields                       |
| Key normalization      | `camelCase` → `snake_case` mapping correctness                                    |

### 13.2 Integration Tests

| Area                | Coverage                                                    |
| ------------------- | ----------------------------------------------------------- |
| eCX sandbox API     | Live queries against sandbox (phish search, submit, update) |
| Enrichment pipeline | Full passive recon with eCX enrichment enabled              |
| Submission pipeline | End-to-end submit → verify on sandbox                       |
| Cache layer         | TTL expiry, cache hit/miss behavior                         |

### 13.3 Test Fixtures

```python
# tests/fixtures/ecx_responses.py

ECX_PHISH_SEARCH_RESPONSE = {
    "data": [
        {
            "id": 112124609,
            "discoveredAt": 1772733665,
            "brand": "Rakuten",
            "confidence": 100,
            "url": "https://test-scam.example.com/",
            "status": "active",
            "ip": ["172.31.138.180"],
            "asn": [20940],
            "tld": "com",
        }
    ],
    "current_page": 1,
    "total": 1,
    "page_size": 10,
}

ECX_CRYPTO_SEARCH_RESPONSE = {
    "data": [
        {
            "id": 1292752,
            "currency": "BTC",
            "address": "19U1xBf2UZeLfPkVh1Gu3WGHheYCzjsVxs",
            "crimeCategory": "scam",
            "siteLink": "fake-exchange.com",
            "confidence": 100,
            "procedure": "manual",
        }
    ],
    "current_page": 1,
    "total": 1,
}
```

### 13.4 Sandbox Test Suite

A dedicated test module (`tests/integration/test_ecx_sandbox.py`) runs against the eCX sandbox environment. These tests:

- Require `SSI_ECX__API_KEY` to be set
- Are excluded from CI by default (marked `@pytest.mark.ecx_sandbox`)
- Are run manually during integration validation

---

## 14. Implementation Plan

### Phase 1 — Consume (Enrichment)

| Step | Task                                                                         | Dependencies |
| ---- | ---------------------------------------------------------------------------- | ------------ |
| 1.1  | Add `ECXSettings` to settings model and `[ecx]` to `settings.default.toml`   | None         |
| 1.2  | Create `ssi/src/ssi/models/ecx.py` with Pydantic models                      | None         |
| 1.3  | Create `ssi/config/ecx_currency_map.json`                                    | None         |
| 1.4  | Implement `ECXClient` in `ssi/src/ssi/osint/ecrimex.py` (query methods only) | 1.1, 1.2     |
| 1.5  | Implement `enrich_from_ecx()` and `enrich_wallets_from_ecx()`                | 1.4          |
| 1.6  | Wire enrichment into orchestrator passive recon                              | 1.5          |
| 1.7  | Add eCX section to report templates                                          | 1.6          |
| 1.8  | Add eCX indicators to STIX bundle generation                                 | 1.6          |
| 1.9  | Alembic migration for `ecx_enrichments` cache table                          | None         |
| 1.10 | CLI: `ssi ecx search` commands                                               | 1.4          |
| 1.11 | API: `GET /investigate/{id}/ecx`, `POST /ecx/search/*`                       | 1.4          |
| 1.12 | Unit tests for client, models, enrichment pipeline                           | 1.4–1.8      |
| 1.13 | Sandbox integration tests                                                    | 1.4          |
| 1.14 | Expand wallet allowlist with XLM, XMR, XZC, ZEC patterns                     | None         |
| 1.15 | Settings unit tests for ECXSettings                                          | 1.1          |
| 1.16 | Docs update: env var reference, config guide                                 | 1.1          |

**Can start immediately** with current `phish` module access. Other module queries will gracefully degrade (log + skip) until access is granted.

### Phase 2 — Contribute (Submission)

| Step | Task                                                          | Dependencies |
| ---- | ------------------------------------------------------------- | ------------ |
| 2.1  | Implement `ECXClient` submit/update/note methods              | Phase 1      |
| 2.2  | Alembic migration for `ecx_submissions` table                 | None         |
| 2.3  | Implement `ECXSubmissionService` with governance logic        | 2.1, 2.2     |
| 2.4  | Wire submission into post-investigation pipeline              | 2.3          |
| 2.5  | API: submission management endpoints (approve/reject/retract) | 2.3          |
| 2.6  | CLI: `ssi ecx submit`, `ssi ecx status`, `ssi ecx retract`    | 2.3          |
| 2.7  | UI: submission status in investigation detail                 | 2.5          |
| 2.8  | UI: submission review queue with bulk actions                 | 2.5          |
| 2.9  | Unit tests for submission service, dedup, governance          | 2.3          |
| 2.10 | Sandbox integration tests for submit/update                   | 2.1          |
| 2.11 | Docs: submission governance guide                             | 2.3          |

**Blocked on**: Data sharing agreement with APWG. Development can proceed against sandbox.

### Phase 3 — Orchestrate (Full Bidirectional)

| Step | Task                                                  | Dependencies |
| ---- | ----------------------------------------------------- | ------------ |
| 3.1  | Implement `ECXPoller` service                         | Phase 1      |
| 3.2  | Polling state tracking (last_polled_id per module)    | 3.1          |
| 3.3  | Wire poller to investigation trigger                  | 3.1          |
| 3.4  | Cloud Scheduler + Cloud Run Job for polling           | 3.1          |
| 3.5  | Campaign correlation logic (wallet/IP/ASN clustering) | Phase 1 + 2  |
| 3.6  | UI: eCX intelligence feed page                        | 3.1          |
| 3.7  | UI: campaign correlation view                         | 3.5          |
| 3.8  | CLI: `ssi ecx poll`                                   | 3.1          |
| 3.9  | Unit tests for poller, correlation                    | 3.1, 3.5     |
| 3.10 | Integration tests for polling + auto-trigger          | 3.3          |

**Depends on**: Phase 1 + Phase 2 stable, eCX module access for polling targets.

---

## 15. Deployment

### 15.1 Environment Variables (New)

| Variable                         | Required                          | Phase |
| -------------------------------- | --------------------------------- | ----- |
| `SSI_ECX__API_KEY`               | Yes (when enabled)                | 1     |
| `SSI_ECX__ENABLED`               | No (default: false)               | 1     |
| `SSI_ECX__BASE_URL`              | No (default: sandbox)             | 1     |
| `SSI_ECX__ATTRIBUTION`           | No (default: IntelligenceForGood) | 2     |
| `SSI_ECX__SUBMISSION_ENABLED`    | No (default: false)               | 2     |
| `SSI_ECX__AUTO_SUBMIT_THRESHOLD` | No (default: 80)                  | 2     |
| `SSI_ECX__INBOUND_ENABLED`       | No (default: false)               | 3     |

### 15.2 Infrastructure (Terraform)

Phase 1 and 2 require no new infrastructure — eCX queries run within the existing SSI Cloud Run Service (`ssi-svc`).

Phase 3 adds the eCX poller job (defined in `infra/environments/app/dev/terraform.tfvars` under `run_jobs.ecx_poller`):

- **Cloud Run Job** (`ssi-ecx-poller`) — Reuses the `ssi-svc` Docker image with args `["ecx", "poll"]`.
- **Cloud Scheduler** — 15-minute interval (`*/15 * * * *`), created automatically by the `run_jobs` Terraform module.
- **VPC Connector** — Override in `main.tf` (`run_job_vpc_connector_overrides.ecx_poller`) connects the job to Cloud SQL via the serverless VPC connector.

### 15.3 Secret Manager

Add `ssi-ecx-api-key` secret in `i4g-dev` and `i4g-prod` GCP projects (via Terraform in `infra/environments/app/dev/ssi_secrets.tf`).

---

_This TDD is an addendum to the SSI TDD. It describes the eCrimeX integration work stream. For the base SSI system design, see `ssi/docs/tdd.md`._
