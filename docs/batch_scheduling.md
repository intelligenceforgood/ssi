# Batch Scheduling Guide

> **Audience:** Operators and DevOps engineers. For end-user batch usage via CLI, see the [Batch Investigations page](../../docs/book/ssi/batch-investigations.md) on the docs site.

This guide covers infrastructure-level batch patterns — campaign scripts, Cloud Run Jobs, and Cloud Scheduler.

---

## Table of Contents

1. [Local Batch: Campaign Runner](#local-batch-campaign-runner)
2. [Local Batch: URL File](#local-batch-url-file)
3. [Cloud Run Job](#cloud-run-job)
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

## Cloud Run Job

SSI provides a Cloud Run Job image (`ssi-job`) for serverless batch investigations. Each job execution investigates one URL.

### Build and push the job image

```bash
cd ssi/
make push-job
# Equivalent to: scripts/build_image.sh ssi-job dev
```

### Trigger a single job

```bash
gcloud run jobs execute ssi-investigate \
  --region us-central1 \
  --update-env-vars SSI_JOB__URL="https://target-site.com",SSI_JOB__SCAN_TYPE=full
```

### Environment variables

| Variable                   | Default    | Description                         |
| -------------------------- | ---------- | ----------------------------------- |
| `SSI_JOB__URL`             | (required) | Target URL to investigate           |
| `SSI_JOB__SCAN_TYPE`       | `full`     | `passive`, `active`, or `full`      |
| `SSI_JOB__PUSH_TO_CORE`    | `false`    | Push results to i4g core API        |
| `SSI_JOB__TRIGGER_DOSSIER` | `false`    | Queue dossier generation after push |
| `SSI_JOB__DATASET`         | `ssi`      | Dataset label for the core case     |

### CLI equivalent

```bash
conda run -n i4g-ssi ssi job investigate \
  --url "https://target-site.com" \
  --scan-type full \
  --push-to-core
```

---

## Cloud Scheduler (Cron)

Use Google Cloud Scheduler to trigger SSI jobs on a recurring schedule. This is useful for monitoring known scam infrastructure or running periodic sweeps.

### Create a scheduled job

```bash
gcloud scheduler jobs create http ssi-daily-sweep \
  --location us-central1 \
  --schedule "0 6 * * *" \
  --uri "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/i4g-dev/jobs/ssi-investigate:run" \
  --http-method POST \
  --headers "Content-Type=application/json" \
  --message-body '{"overrides":{"containerOverrides":[{"env":[{"name":"SSI_JOB__URL","value":"https://target-site.com"},{"name":"SSI_JOB__SCAN_TYPE","value":"passive"}]}]}}' \
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

For scheduled sweeps over a URL list, create a wrapper Cloud Run Job that:

1. Reads URLs from a GCS bucket (`gs://i4g-dev-ssi-evidence/sweeps/urls.json`)
2. Submits each URL to the SSI API (`POST /investigate`)
3. Collects task IDs and polls for completion

This pattern is used by the campaign runner internally. A Cloud Run Job version is planned for Phase 9.

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

| Workload         | Recommended approach       | Why                                          |
| ---------------- | -------------------------- | -------------------------------------------- |
| < 10 URLs        | API submissions            | Simple, real-time status tracking            |
| 10–100 URLs      | Campaign runner (local)    | Rich console output, aggregate report        |
| 100+ URLs        | Cloud Run Jobs + Scheduler | Serverless scaling, no local resource limits |
| Recurring sweeps | Cloud Scheduler + Job      | Automated, auditable, cost-controlled        |
