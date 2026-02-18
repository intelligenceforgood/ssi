# SSI User Guide

This guide walks you through using the Scam Site Investigator (SSI) to investigate suspicious websites — from basic passive scans to full AI-driven scam funnel traversal. No technical expertise is required to follow these steps.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Verify Your Setup](#3-verify-your-setup)
4. [Your First Investigation (Passive Scan)](#4-your-first-investigation-passive-scan)
5. [Understanding the Results](#5-understanding-the-results)
6. [Full Investigation (AI Agent)](#6-full-investigation-ai-agent)
7. [Batch Investigations](#7-batch-investigations)
8. [Using the API](#8-using-the-api)
9. [Customizing Investigations](#9-customizing-investigations)
10. [Configuration Reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

Before using SSI, you need:

- **Python 3.11 or later** — check with `python3 --version`
- **Ollama** — a local LLM runtime (required for the AI agent). Download from [ollama.com](https://ollama.com)
- **Llama 3.3 model** — pulled via Ollama (see below)

### Install Ollama and pull the model

```bash
# Install Ollama (macOS)
brew install ollama

# Start the Ollama service
ollama serve

# In a new terminal, pull the Llama 3.3 model (~20GB download)
ollama pull llama3.3
```

> **Note**: The Llama 3.3 model requires ~20GB of disk space and runs well on machines with 16GB+ RAM. On Apple Silicon Macs, it uses the GPU automatically.

---

## 2. Installation

```bash
# Clone the repository (if you haven't already)
cd /path/to/i4g/ssi

# Create and activate a virtual environment (pick your preferred tool)
#
# Option A: conda / miniforge
conda create -n i4g-ssi python=3.11
conda activate i4g-ssi
#
# Option B: built-in venv
python3 -m venv .venv
source .venv/bin/activate

# Install SSI with all dependencies
pip install -e ".[dev,test]"

# Install the Playwright browser binary
playwright install chromium
```

Verify the CLI is available:

```bash
ssi --version
```

You should see the version number printed (e.g., `0.1.0`).

---

## 3. Verify Your Setup

Run the settings validation command to confirm everything is configured correctly:

```bash
ssi settings validate
```

Expected output:

```
✅ Settings valid
   Environment: local
   LLM provider: ollama
   Evidence dir: data/evidence
```

If Ollama is not running, you will see a warning — start it with `ollama serve` in a separate terminal.

You can also inspect the full resolved configuration:

```bash
ssi settings show
```

---

## 4. Your First Investigation (Passive Scan)

A passive scan collects infrastructure intelligence about a URL **without** interacting with the site (no form filling, no clicking). This is the safest starting point.

### Example: Investigating a suspicious URL

```bash
ssi investigate url "https://etsyorders.com" --passive
```

This command:

1. Looks up WHOIS registration data (who owns the domain, when it was created)
2. Resolves DNS records (what servers the domain points to)
3. Inspects the SSL/TLS certificate (is it self-signed? who issued it?)
4. Geolocates the hosting IP (what country/provider hosts it)
5. Takes a full-page screenshot
6. Captures the DOM (the page's full HTML structure)
7. Records the HAR file (all network requests the page makes)
8. Inventories all form fields (what information the site asks for)
9. Checks the URL against VirusTotal (is it flagged as malicious?)
10. Submits to urlscan.io (page analysis and contacted domains)

### Where to find results

After the investigation completes, SSI creates a timestamped folder under `data/evidence/`:

```
data/evidence/etsyorders_com_20260218_143022/
├── investigation.json      # Full structured result (machine-readable)
├── report.md               # Human-readable investigation report
├── leo_evidence_report.md  # Law enforcement evidence summary
├── stix_bundle.json        # STIX 2.1 threat indicators (IOCs)
├── evidence.zip            # All artifacts with chain-of-custody manifest
├── screenshot.png          # Full-page screenshot
├── dom.html                # DOM snapshot
└── network.har             # HAR network recording
```

Open `report.md` in any text editor or Markdown viewer for a human-readable summary of the investigation.

---

## 5. Understanding the Results

### The Investigation Report (`report.md`)

The report is organized into sections:

- **Target Information** — URL, domain, investigation timestamp
- **WHOIS Data** — registrar, creation date, expiration date, registrant info, nameservers
- **DNS Records** — A, MX, NS, TXT records showing the site's infrastructure
- **SSL Certificate** — issuer, validity period, whether it's self-signed
- **IP Geolocation** — hosting country, city, ASN, organization
- **Form Fields** — every input the site presents (name, email, credit card, SSN, etc.)
- **VirusTotal** — how many security engines flag the URL as malicious
- **External Resources** — third-party scripts, stylesheets, and iframes loaded by the page
- **Risk Assessment** — overall risk score and fraud classification

### Key things to look for

| Finding                                            | What it means                                   |
| -------------------------------------------------- | ----------------------------------------------- |
| Domain created very recently (days/weeks ago)      | Scam sites are typically short-lived            |
| WHOIS data is privacy-protected or missing         | Common for scam sites hiding ownership          |
| Self-signed or recently issued SSL cert            | Legitimate businesses use established CAs       |
| Hosted in unexpected country for the claimed brand | e.g., "Etsy" hosted in Russia or China          |
| Form asks for SSN, credit card, or bank details    | These are red flags for a shopping/brand site   |
| VirusTotal detections > 0                          | Security engines have already flagged it        |
| External scripts from suspicious domains           | May indicate phishing kits or data exfiltration |

### The Evidence ZIP (`evidence.zip`)

This is the package you would hand to law enforcement. It contains:

- All investigation artifacts (screenshots, DOM, HAR, reports)
- `manifest.json` with SHA-256 hashes for every file (chain-of-custody proof)
- A legal notice confirming all PII used was synthetic

### STIX Bundle (`stix_bundle.json`)

A machine-readable threat intelligence file in STIX 2.1 format, containing:

- IP addresses, domains, and URLs as threat indicators
- Relationships between indicators and the scam infrastructure
- Can be imported into threat intelligence platforms (MISP, OpenCTI, etc.)

---

## 6. Full Investigation (AI Agent)

A full investigation goes beyond passive scanning — SSI launches an AI agent that **interacts** with the scam site like a real victim would.

### Running a full investigation

```bash
ssi investigate url "https://etsyorders.com"
```

Without the `--passive` flag, SSI performs the passive scan first, then:

1. **Generates a synthetic identity** — a fake but realistic person with name, address, email, phone, SSN, credit card, etc. All data is provably non-real (SSNs use the 900–999 IRS invalid range, credit cards use Stripe test BINs).

2. **Launches the AI agent** — the agent opens the site in a browser and reasons about what to do next, step by step:
   - It reads the page content and identifies interactive elements
   - It decides which forms to fill, which buttons to click
   - It types in the synthetic identity's information
   - It follows the scam through multiple pages (login → details → payment → confirmation)
   - It records a screenshot at every step

3. **Records what PII the scam collects** — SSI tracks exactly which personal data fields the site asked for and at which step.

4. **Classifies the scam** — using the i4g fraud taxonomy (intent, channel, techniques, actions, persona) with a computed risk score from 0–100.

### Additional outputs from a full investigation

Beyond the passive scan outputs, a full investigation produces:

- **Agent session log** — step-by-step record of every action the agent took
- **Per-step screenshots** — before and after each interaction
- **PII collection map** — which data the scam asked for, in what order
- **Fraud classification** — five-axis taxonomy labels with confidence scores

### Example: Walk through a fake Etsy order scam

Suppose you receive a text message saying "Your Etsy order has been delayed, verify at etsyorders.com." Here's how to investigate:

```bash
# Step 1: Quick passive scan to see what we're dealing with
ssi investigate url "https://etsyorders.com" --passive --format both

# Step 2: Review the report
cat data/evidence/etsyorders_com_*/report.md

# Step 3: If it looks suspicious, run the full investigation
ssi investigate url "https://etsyorders.com" --format both

# Step 4: Review the complete evidence package
ls data/evidence/etsyorders_com_*/
cat data/evidence/etsyorders_com_*/report.md
```

---

## 7. Batch Investigations

To investigate multiple URLs at once, create a text file with one URL per line:

```bash
# Create a file with URLs to investigate
cat > urls.txt << 'EOF'
https://etsyorders.com
https://fedex-delivery-update.com
https://amazon-refund-claim.net
# Lines starting with # are comments and are skipped
EOF

# Run batch investigation (passive only)
ssi investigate batch urls.txt --passive

# Run batch investigation (full)
ssi investigate batch urls.txt

# Specify a custom output directory
ssi investigate batch urls.txt --output ./my-evidence
```

Each URL gets its own timestamped subdirectory under the output folder.

---

## 8. Using the API

SSI also provides a REST API for integration with other tools.

### Start the API server

```bash
uvicorn ssi.api.app:app --reload --port 8100
```

Or using the Makefile:

```bash
make serve
```

### Submit an investigation

```bash
curl -X POST http://localhost:8100/investigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://etsyorders.com", "passive_only": true}'
```

Response:

```json
{
  "investigation_id": "abc123",
  "status": "pending"
}
```

### Check investigation status

```bash
curl http://localhost:8100/investigate/abc123
```

Response (when complete):

```json
{
  "investigation_id": "abc123",
  "status": "completed",
  "result": { ... }
}
```

### Health check

```bash
curl http://localhost:8100/health
```

---

## 9. Customizing Investigations

### Skip specific checks

If a check is slow or not needed, skip it:

```bash
# Skip WHOIS (useful if the lookup times out)
ssi investigate url "https://example.com" --passive --skip-whois

# Skip VirusTotal (if you don't have an API key)
ssi investigate url "https://example.com" --passive --skip-virustotal

# Skip urlscan.io
ssi investigate url "https://example.com" --passive --skip-urlscan

# Skip screenshot capture
ssi investigate url "https://example.com" --passive --skip-screenshot

# Combine multiple skips
ssi investigate url "https://example.com" --passive --skip-whois --skip-virustotal
```

### Choose output format

```bash
# JSON only (default)
ssi investigate url "https://example.com" --passive --format json

# Markdown only
ssi investigate url "https://example.com" --passive --format markdown

# Both JSON and Markdown
ssi investigate url "https://example.com" --passive --format both
```

### Custom output directory

```bash
ssi investigate url "https://example.com" --passive --output ./custom-evidence-dir
```

### Push results to i4g core platform

If you have the i4g core API running locally:

```bash
ssi investigate url "https://example.com" --push-to-core --trigger-dossier
```

---

## 10. Configuration Reference

SSI settings can be customized through environment variables, TOML config files, or CLI flags.

### Environment Variables

All environment variables use the `SSI_` prefix. Use double underscores (`__`) for nested settings.

#### General

| Variable    | Description          | Default |
| ----------- | -------------------- | ------- |
| `SSI_ENV`   | Environment name     | `local` |
| `SSI_DEBUG` | Enable debug logging | `false` |

#### LLM

| Variable                            | Description                       | Default                  |
| ----------------------------------- | --------------------------------- | ------------------------ |
| `SSI_LLM__PROVIDER`                 | LLM provider (`ollama`, `vertex`) | `ollama`                 |
| `SSI_LLM__MODEL`                    | Model name                        | `llama3.3`               |
| `SSI_LLM__OLLAMA_BASE_URL`          | Ollama API URL                    | `http://localhost:11434` |
| `SSI_LLM__TEMPERATURE`              | Sampling temperature              | `0.1`                    |
| `SSI_LLM__MAX_TOKENS`               | Max tokens per response           | `4096`                   |
| `SSI_LLM__TOKEN_BUDGET_PER_SESSION` | Max tokens per investigation      | `50000`                  |

#### Browser

| Variable                    | Description             | Default |
| --------------------------- | ----------------------- | ------- |
| `SSI_BROWSER__HEADLESS`     | Run browser headless    | `true`  |
| `SSI_BROWSER__TIMEOUT_MS`   | Page load timeout (ms)  | `30000` |
| `SSI_BROWSER__RECORD_HAR`   | Record HAR file         | `true`  |
| `SSI_BROWSER__RECORD_VIDEO` | Record video of session | `false` |
| `SSI_BROWSER__SANDBOX`      | Use browser sandbox     | `true`  |

#### OSINT

| Variable                        | Description          | Default                          |
| ------------------------------- | -------------------- | -------------------------------- |
| `SSI_OSINT__VIRUSTOTAL_API_KEY` | VirusTotal API key   | _(empty — skips check)_          |
| `SSI_OSINT__URLSCAN_API_KEY`    | urlscan.io API key   | _(empty — uses search fallback)_ |
| `SSI_OSINT__IPINFO_TOKEN`       | ipinfo.io token      | _(empty — uses free tier)_       |
| `SSI_OSINT__WHOIS_TIMEOUT_SEC`  | WHOIS lookup timeout | `10`                             |
| `SSI_OSINT__DNS_TIMEOUT_SEC`    | DNS lookup timeout   | `5`                              |

#### Evidence

| Variable                        | Description                      | Default         |
| ------------------------------- | -------------------------------- | --------------- |
| `SSI_EVIDENCE__OUTPUT_DIR`      | Evidence output directory        | `data/evidence` |
| `SSI_EVIDENCE__STORAGE_BACKEND` | Storage backend (`local`, `gcs`) | `local`         |
| `SSI_EVIDENCE__GCS_BUCKET`      | GCS bucket name (production)     | _(empty)_       |

#### Identity

| Variable                           | Description                             | Default |
| ---------------------------------- | --------------------------------------- | ------- |
| `SSI_IDENTITY__DEFAULT_LOCALE`     | Faker locale for identity generation    | `en_US` |
| `SSI_IDENTITY__ROTATE_PER_SESSION` | Generate new identity per investigation | `true`  |

#### Stealth

| Variable                             | Description                              | Default       |
| ------------------------------------ | ---------------------------------------- | ------------- |
| `SSI_STEALTH__PROXY_URLS`            | Comma-separated proxy URLs               | _(empty)_     |
| `SSI_STEALTH__ROTATION_STRATEGY`     | Proxy rotation (`round_robin`, `random`) | `round_robin` |
| `SSI_STEALTH__RANDOMIZE_FINGERPRINT` | Randomize browser fingerprint            | `true`        |
| `SSI_STEALTH__APPLY_STEALTH_SCRIPTS` | Inject anti-detection scripts            | `true`        |

#### CAPTCHA

| Variable                            | Description                                                  | Default |
| ----------------------------------- | ------------------------------------------------------------ | ------- |
| `SSI_CAPTCHA__STRATEGY`             | CAPTCHA handling (`skip`, `wait`, `accessibility`, `solver`) | `skip`  |
| `SSI_CAPTCHA__WAIT_SECONDS`         | Seconds to wait (if strategy is `wait`)                      | `15`    |
| `SSI_CAPTCHA__SCREENSHOT_ON_DETECT` | Screenshot when CAPTCHA detected                             | `true`  |

#### Cost

| Variable                                 | Description                     | Default |
| ---------------------------------------- | ------------------------------- | ------- |
| `SSI_COST__BUDGET_PER_INVESTIGATION_USD` | Max cost per investigation      | `1.0`   |
| `SSI_COST__WARN_AT_PCT`                  | Warn when budget reaches this % | `80`    |
| `SSI_COST__ENABLED`                      | Enable cost tracking            | `true`  |

#### Integration

| Variable                           | Description                           | Default                 |
| ---------------------------------- | ------------------------------------- | ----------------------- |
| `SSI_INTEGRATION__CORE_API_URL`    | i4g core API URL                      | `http://localhost:8000` |
| `SSI_INTEGRATION__PUSH_TO_CORE`    | Auto-push results to core             | `false`                 |
| `SSI_INTEGRATION__TRIGGER_DOSSIER` | Trigger dossier generation after push | `false`                 |
| `SSI_INTEGRATION__DATASET`         | Dataset label for core cases          | `ssi`                   |

### Config File Overrides

Create `config/settings.local.toml` (gitignored) for persistent local overrides:

```toml
[osint]
virustotal_api_key = "your-key-here"
ipinfo_token = "your-token-here"

[browser]
headless = false  # Watch the browser in action

[llm]
model = "llama3.3"
temperature = 0.1
```

---

## 11. Troubleshooting

### "Connection refused" when running investigations

Ollama is not running. Start it:

```bash
ollama serve
```

### WHOIS lookup times out

Some WHOIS servers are slow or rate-limited. Skip it:

```bash
ssi investigate url "https://example.com" --passive --skip-whois
```

Or increase the timeout in `config/settings.local.toml`:

```toml
[osint]
whois_timeout_sec = 30
```

### VirusTotal check skipped

You need an API key. Get a free one at [virustotal.com](https://www.virustotal.com/gui/join-us) and set it:

```bash
export SSI_OSINT__VIRUSTOTAL_API_KEY="your-key-here"
```

Or add it to `config/settings.local.toml`.

### Browser crashes or hangs

Try disabling the sandbox:

```bash
export SSI_BROWSER__SANDBOX=false
```

Or increase the timeout:

```bash
export SSI_BROWSER__TIMEOUT_MS=60000
```

### AI agent gets stuck in a loop

The agent has built-in limits (20 steps, 50K token budget). If it consistently fails on a particular site, try passive-only mode first.

### "playwright install" fails

Ensure you have system dependencies for Chromium. On Ubuntu/Debian:

```bash
playwright install-deps chromium
```

On macOS, it should work without additional system deps.

### Investigation takes too long

Passive-only scans are fast (30–60 seconds). Full investigations with the AI agent take 2–5 minutes depending on the site complexity and your hardware.

To speed things up:

- Skip checks you don't need (`--skip-whois`, `--skip-virustotal`)
- Reduce the agent's step limit via `SSI_LLM__TOKEN_BUDGET_PER_SESSION`
- Ensure Ollama is using GPU acceleration (check with `ollama ps`)
