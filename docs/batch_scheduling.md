# Batch Scheduling Guide

> **Audience:** Operators and DevOps engineers. For end-user batch usage via CLI, see the [Batch Investigations page](../../docs/book/ssi/batch-investigations.md) on the docs site.

This guide covers infrastructure-level batch patterns — campaign scripts, Cloud Run Jobs, and Cloud Scheduler.

---

## Table of Contents

1. [Local Batch: Campaign Runner](#local-batch-campaign-runner)
2. [Local Batch: URL File](#local-batch-url-file)
3. [Service-Based Investigations](#service-based-investigations)
4. [Cloud Scheduler (Cron)](#cloud-scheduler-cron)
5. [API-Driven Batch](#api-driven-batch)
6. [Cost & Concurrency](#cost--concurrency)

---

## Local Batch: Campaign Runner

The `scripts/campaign_runner.py` script executes investigations against a curated catalog of test URLs organized by scam type. It produces per-URL evidence directories and an aggregate summary.

```bash
# Run all safe test URLs (default — no real scam sites)
conda run -n i4g-ssi python scripts/campaign_runner.py

# Run passive-only (faster, no LLM agent interaction)
conda run -n i4g-ssi python scripts/campaign_runner.py --passive

# Filter by scam category
conda run -n i4g-ssi python scripts/campaign_runner.py --category phishing

# Run active mode (requires Ollama running)
conda run -n i4g-ssi python scripts/campaign_runner.py --active
```

### Campaign output

Results are written to `data/campaigns/campaign_<id>/`:

```
data/campaigns/campaign_a1b2c3d4/
├── <url-slug>/          # Per-URL evidence directory
│   ├── result.json
│   ├── screenshots/
│   └── report.pdf
├── summary.json          # Aggregate results
└── campaign_report.md    # Human-readable summary
```

---

## Local Batch: URL File

For custom URL lists, pass a text file with one URL per line:

```bash
conda run -n i4g-ssi python scripts/campaign_runner.py --url-file urls.txt
```

Or investigate a single URL:

```bash
conda run -n i4g-ssi python scripts/campaign_runner.py --url "https://suspicious-site.com"
```

### URL file format

```text
# Comments start with #
https://suspicious-site-1.com
https://suspicious-site-2.com/login
https://another-scam.xyz
```

---

## Service-Based Investigations

SSI runs as a Cloud Run Service. Investigations are triggered via HTTP POST endpoints. There is no separate Cloud Run Job image.

### Build and push the service image

```bash
cd ssi/
make push-svc
# Equivalent to: scripts/build_image.sh ssi-svc dev
```

### Trigger a single investigation

```bash
curl -X POST https://ssi-svc-<hash>.run.app/trigger/investigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target-site.com", "scan_type": "full", "push_to_core": true}'
```

The endpoint returns `202 Accepted` with a `scan_id` for status tracking.

### CLI equivalent

```bash
conda run -n i4g-ssi ssi job investigate \
  --url "https://target-site.com" \
  --scan-type full \
  --push-to-core
```

### Batch investigations (manifest-based)

For processing multiple URLs, use the batch endpoint. It accepts an inline manifest or a GCS URI.

#### Manifest format

```json
[
  { "url": "https://scam1.example.com", "scan_type": "full" },
  { "url": "https://scam2.example.com", "scan_type": "passive" },
  { "url": "https://scam3.example.com" }
]
```

Each entry requires `url`; `scan_type` defaults to the request-level setting (default: `full`).

#### Trigger a batch investigation

```bash
# Inline manifest
curl -X POST https://ssi-svc-<hash>.run.app/trigger/batch \
  -H "Content-Type: application/json" \
  -d '{
    "manifest": [
      {"url": "https://scam1.example.com"},
      {"url": "https://scam2.example.com"}
    ],
    "default_scan_type": "full",
    "push_to_core": true
  }'

# GCS manifest URI
curl -X POST https://ssi-svc-<hash>.run.app/trigger/batch \
  -H "Content-Type: application/json" \
  -d '{"manifest_uri": "gs://i4g-dev-ssi-evidence/manifests/batch1.json"}'
```

#### CLI equivalent

```bash
conda run -n i4g-ssi ssi job batch \
  --manifest manifests/batch1.json \
  --scan-type full \
  --push-to-core
```

See [batch.py](../src/ssi/worker/batch.py) for the manifest loading implementation.

---

## Cloud Scheduler (Cron)

Use Google Cloud Scheduler to trigger SSI investigations on a recurring schedule via the service HTTP endpoints.

### Create a scheduled single investigation

```bash
gcloud scheduler jobs create http ssi-daily-sweep \
  --location us-central1 \
  --schedule "0 6 * * *" \
  --uri "https://ssi-svc-<hash>.run.app/trigger/investigate" \
  --http-method POST \
  --headers "Content-Type=application/json" \
  --message-body '{"url":"https://target-site.com","scan_type":"passive","push_to_core":true}' \
  --oauth-service-account-email sa-ssi@i4g-dev.iam.gserviceaccount.com
```

### Schedule patterns

| Pattern       | Description                   |
| ------------- | ----------------------------- |
| `0 6 * * *`   | Daily at 06:00 UTC            |
| `0 */4 * * *` | Every 4 hours                 |
| `0 6 * * 1`   | Weekly on Monday at 06:00 UTC |
| `0 6 1 * *`   | Monthly on the 1st at 06:00   |

### Batch sweep (multiple URLs)

For scheduled sweeps over a URL list, call the batch endpoint with a GCS manifest URI:

```bash
gcloud scheduler jobs create http ssi-weekly-sweep \
  --location us-central1 \
  --schedule "0 6 * * 1" \
  --uri "https://ssi-svc-<hash>.run.app/trigger/batch" \
  --http-method POST \
  --headers "Content-Type=application/json" \
  --message-body '{"manifest_uri":"gs://i4g-dev-ssi-evidence/sweeps/weekly.json","default_scan_type":"passive","push_to_core":true}' \
  --oauth-service-account-email sa-ssi@i4g-dev.iam.gserviceaccount.com
```

Maintain the manifest as a JSON file in GCS (`gs://i4g-dev-ssi-evidence/sweeps/weekly.json`). Update the manifest to add or remove URLs without redeploying the service.

---

## API-Driven Batch

Submit investigations programmatically via the SSI REST API:

```python
import httpx
import time

API_URL = "http://localhost:8100"  # or Cloud Run service URL

urls = [
    "https://suspicious-site-1.com",
    "https://suspicious-site-2.com",
]

# Submit all investigations
task_ids = []
for url in urls:
    resp = httpx.post(f"{API_URL}/investigate", json={"url": url, "scan_type": "passive"})
    if resp.status_code == 200:
        task_ids.append(resp.json()["task_id"])
    elif resp.status_code == 429:
        print(f"At capacity — waiting before retrying {url}")
        time.sleep(30)
        # Retry logic here

# Poll for results
for task_id in task_ids:
    while True:
        status = httpx.get(f"{API_URL}/tasks/{task_id}").json()
        if status["status"] in ("completed", "failed"):
            print(f"{task_id}: {status['status']}")
            break
        time.sleep(5)
```

> **HTTP 429**: The API enforces a concurrent investigation limit (default: 5). When all slots are occupied, new submissions receive a 429 response. Implement retry-with-backoff in batch clients.

---

## Cost & Concurrency

### Budget enforcement

The `CostTracker` enforces per-investigation budgets. In batch scenarios, each investigation tracks its own costs independently. Configure the budget via settings:

```bash
export SSI_COST__BUDGET_USD=2.0      # Max spend per investigation
export SSI_COST__ENABLED=true        # Enable cost tracking
```

If an investigation exceeds its budget, it completes with partial results rather than failing. The orchestrator preserves all data collected up to the budget gate.

### Concurrent limit

The API limits concurrent investigations to prevent resource exhaustion:

```bash
export SSI_API__MAX_CONCURRENT_INVESTIGATIONS=5  # Default: 5
```

For batch workloads, either:

- **Rate-limit submissions** on the client side (recommended)
- **Increase the limit** if infrastructure supports it
- **Use Cloud Run Jobs** instead of the API — each job runs independently with its own resource allocation

### Batch recommendations

| Workload         | Recommended approach       | Why                                   |
| ---------------- | -------------------------- | ------------------------------------- |
| < 10 URLs        | API submissions            | Simple, real-time status tracking     |
| 10–100 URLs      | Campaign runner (local)    | Rich console output, aggregate report |
| 100+ URLs        | Batch endpoint + Scheduler | Serverless, no local resource limits  |
| Recurring sweeps | Cloud Scheduler + Service  | Automated, auditable, cost-controlled |
