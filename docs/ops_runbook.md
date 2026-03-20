# SSI Operations Runbook

> **Last Verified:** March 2026
>
> Operational procedures for the Scam Site Investigator (SSI) service.
> For setup and development, see [developer_guide.md](developer_guide.md).
> For failure mode reference, see [failure_modes.md](failure_modes.md).

---

## Table of Contents

1. [Service Overview](#1-service-overview)
2. [Starting and Stopping the Service](#2-starting-and-stopping-the-service)
3. [Triggering Investigations](#3-triggering-investigations)
4. [Monitoring Investigations](#4-monitoring-investigations)
5. [Intervening in Stuck Investigations](#5-intervening-in-stuck-investigations)
6. [eCX Poller Operations](#6-ecx-poller-operations)
7. [Cloud Run Operations](#7-cloud-run-operations)
8. [Secrets Rotation](#8-secrets-rotation)
9. [Common Failure Scenarios](#9-common-failure-scenarios)
10. [Escalation Path](#10-escalation-path)

---

## 1. Service Overview

| Item                          | Value                                                             |
| ----------------------------- | ----------------------------------------------------------------- |
| Service name                  | `ssi-svc`                                                         |
| Cloud Run region              | `us-central1`                                                     |
| Default port                  | `8100`                                                            |
| Image repo                    | `us-central1-docker.pkg.dev/{project}/applications/ssi-svc:{tag}` |
| Service account               | `sa-ssi`                                                          |
| Health endpoint               | `GET /health`                                                     |
| Max concurrent investigations | `5` (configurable via `SSI_API__MAX_CONCURRENT_INVESTIGATIONS`)   |

The SSI service runs **three types of tasks**:

- **Interactive investigations**: triggered via API, long-running (seconds to minutes), browser automation
- **eCX polling**: scheduled via Cloud Scheduler every 15 minutes
- **Report serving**: fast reads from investigation results

---

## 2. Starting and Stopping the Service

### Local development

```bash
# Start the SSI API server
conda run -n i4g-ssi uvicorn ssi.api.app:app --reload --port 8100

# Verify it's running
curl http://localhost:8100/health
```

### Cloud Run (GCP)

The service is managed by Terraform and deployed via CI/CD. Manual operations:

```bash
# Check service status
gcloud run services describe ssi-svc --region=us-central1 --project=i4g-dev

# Redeploy with latest image
gcloud run services update ssi-svc \
  --image us-central1-docker.pkg.dev/i4g-dev/applications/ssi-svc:dev \
  --region us-central1 --project i4g-dev

# Scale to zero (stop taking traffic)
gcloud run services update ssi-svc --max-instances=0 --region=us-central1 --project=i4g-dev

# Restore to normal
gcloud run services update ssi-svc --max-instances=10 --region=us-central1 --project=i4g-dev
```

---

## 3. Triggering Investigations

### Via CLI (local)

```bash
# Single URL, full pipeline
conda run -n i4g-ssi ssi investigate url https://suspicious-site.example.com

# Passive recon only (no browser interaction)
conda run -n i4g-ssi ssi investigate url https://suspicious-site.example.com --scan-type passive

# Active interaction only
conda run -n i4g-ssi ssi investigate url https://suspicious-site.example.com --scan-type active

# Batch from file
conda run -n i4g-ssi ssi investigate batch --input-file urls.txt
```

### Via API

```bash
# Trigger investigation
curl -X POST http://localhost:8100/investigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.example.com", "scan_type": "full"}'

# Returns:
# {"investigation_id": "abc123", "case_id": "def456", "status": "queued"}

# Poll status
curl http://localhost:8100/investigate/abc123
```

### Via the Analyst Console

Analysts can submit URLs from the `/ssi` page in the i4g-console. Investigations appear in the `/ssi/investigations` list.

### Via Cloud Run Job (production)

The `ssi-ecx-poller` Cloud Run job triggers investigations automatically for new eCX signals.

To manually trigger a bulk run:

```bash
gcloud run jobs execute ssi-ecx-poller --region=us-central1 --project=i4g-dev
```

---

## 4. Monitoring Investigations

### Real-time via WebSocket

```javascript
const ws = new WebSocket("ws://localhost:8100/ws/monitor/{investigation_id}");
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg.type: state_change | screenshot | action | guidance_needed | wallet_found | complete | error
};
```

### Via API polling

```bash
# Poll every 5 seconds
while true; do
  curl -s http://localhost:8100/investigate/{id} | python3 -m json.tool | grep '"status"'
  sleep 5
done
```

### Via Cloud Logging (production)

```bash
# Stream logs for the SSI service
gcloud logging read \
  'resource.type="cloud_run_revision" resource.labels.service_name="ssi-svc"' \
  --limit=50 --project=i4g-dev --format='value(textPayload)' --freshness=1h
```

### Key log messages to watch

| Message                       | Significance                                  |
| ----------------------------- | --------------------------------------------- |
| `"status": "guidance_needed"` | Browser is stuck; analyst intervention needed |
| `"wallet_found"`              | Wallet address extracted                      |
| `"phase_1_complete"`          | Passive recon done                            |
| `"phase_2_complete"`          | Active interaction done                       |
| `"investigation_complete"`    | All phases done, evidence packaged            |
| `"investigation_failed"`      | Pipeline error; check `error_message` field   |
| `"budget_exceeded"`           | Cost cap hit; investigation halted            |

---

## 5. Intervening in Stuck Investigations

When an investigation enters `guidance_needed` state, the browser automation is waiting for analyst input.

### Via the Analyst Console

1. Open `/ssi/investigations/{id}` in the console
2. Click the **Live Monitor** tab
3. View the current screenshot and the action log
4. Use the guidance panel to send a command:
   - **Click**: specify a CSS selector or text to click
   - **Type**: specify a selector and text to type
   - **Skip**: skip the current state and continue
   - **Continue**: retry the current state

### Via WebSocket (programmatic)

```bash
# Send a guidance command to unblock
wscat -c "ws://localhost:8100/ws/guidance/{investigation_id}"
# Then send:
# {"type": "skip", "reason": "CAPTCHA encountered - moving to next step"}
```

### Timeout behavior

If no guidance is received within `stuck_threshold` actions (default: 8 for `FIND_REGISTER`, 15 for `FILL_REGISTER`), the investigation marks the state as failed and moves to the next phase if possible, or marks the investigation as partially complete.

---

## 6. eCX Poller Operations

The `ssi-ecx-poller` Cloud Scheduler job polls the eCX API every 15 minutes.

### Check last successful run

```bash
gcloud run jobs executions list --job=ssi-ecx-poller \
  --region=us-central1 --project=i4g-dev \
  --format='table(name, status, startTime, completionTime)'
```

### Manually trigger the poller

```bash
gcloud run jobs execute ssi-ecx-poller --region=us-central1 --project=i4g-dev
```

### Pause the poller (e.g., during eCX outage)

```bash
gcloud scheduler jobs pause ssi-ecx-poller-schedule \
  --location=us-central1 --project=i4g-dev
```

### Resume the poller

```bash
gcloud scheduler jobs resume ssi-ecx-poller-schedule \
  --location=us-central1 --project=i4g-dev
```

### Rotate the eCX API key

```bash
# Update the secret
echo -n "new-api-key" | gcloud secrets versions add ssi-ecx-api-key \
  --data-file=- --project=i4g-dev

# Deploy triggers automatic pickup of new secret version on next Cold Start
# Or force a redeploy:
gcloud run services update ssi-svc --region=us-central1 --project=i4g-dev
```

---

## 7. Cloud Run Operations

### Check current revision traffic

```bash
gcloud run services describe ssi-svc --region=us-central1 --project=i4g-dev \
  --format='value(status.traffic)'
```

### View recent errors

```bash
gcloud logging read \
  'resource.type="cloud_run_revision" resource.labels.service_name="ssi-svc" severity>=ERROR' \
  --project=i4g-dev --limit=20 --format='value(timestamp, textPayload)'
```

### Get the service URI

```bash
gcloud run services describe ssi-svc --region=us-central1 --project=i4g-dev \
  --format='value(status.url)'
```

### Force a cold start (to pick up new secrets)

The SSI service reads secrets at startup. To force a restart after rotating a secret:

```bash
# Deploy same image — Cloud Run creates a new revision
gcloud run services update ssi-svc --region=us-central1 --project=i4g-dev \
  --image=$(gcloud run services describe ssi-svc --region=us-central1 \
  --project=i4g-dev --format='value(spec.template.spec.containers[0].image)')
```

---

## 8. Secrets Rotation

All SSI secrets are in Secret Manager with prefix `ssi-`:

| Secret ID                | Purpose                         | Rotation frequency        |
| ------------------------ | ------------------------------- | ------------------------- |
| `ssi-proxy-credentials`  | Residential proxy auth (Decodo) | When credentials change   |
| `ssi-virustotal-api-key` | VirusTotal OSINT enrichment     | Annually or on compromise |
| `ssi-urlscan-api-key`    | urlscan.io submission           | Annually or on compromise |
| `ssi-ipinfo-token`       | IP geolocation                  | Annually                  |
| `ssi-ecx-api-key`        | eCX data feed API key           | Per eCX rotation policy   |

Rotation procedure:

1. Generate or receive new credential
2. `echo -n "new-value" | gcloud secrets versions add {secret-id} --data-file=- --project={project}`
3. Validate the new version: `gcloud secrets versions access latest --secret={secret-id} --project={project}`
4. Force SSI service cold start (see above) to pick up new version
5. Run a test investigation to confirm OSINT enrichment works
6. Disable the old secret version: `gcloud secrets versions disable {old-version} --secret={secret-id} --project={project}`

---

## 9. Common Failure Scenarios

### Investigation stuck at CAPTCHA

**Symptom:** `status: guidance_needed`, screenshot shows CAPTCHA
**Action:** Use guidance panel to skip state, or mark investigation as partial
**Prevention:** Residential proxy rotation (Decodo handles this automatically)

### VirusTotal / urlscan rate limit

**Symptom:** OSINT enrichment shows partial results, logs show 429 errors
**Action:** Check current quota usage; stagger batch investigations
**Fix:** Upgrade API tier or reduce investigation frequency

### SSI service can't reach core-svc

**Symptom:** `push_to_core` failures in SSI logs; cases not appearing in analyst console
**Action:** Check `I4G_SSI__CORE_API_URL` env var; check core-svc health; check OIDC token issuance
**Debug:** `gcloud logging read 'resource.labels.service_name="ssi-svc"' --filter='push_to_core'`

### Browser crashes / memory exhaustion

**Symptom:** Investigation fails with `BrowserError` or `MemoryError`
**Action:** Check Cloud Run memory allocation (ssi-svc requires ≥2Gi); reduce `max_concurrent_investigations`
**Fix:** Increase Cloud Run memory via Terraform or `gcloud run services update --memory=4Gi`

### Playbook mismatch (new scam site layout)

**Symptom:** Investigation completes on some sites, fails/partial on others matching same pattern
**Action:** Update or create a playbook in `config/playbooks/`
**Reference:** [playbook_authoring.md](playbook_authoring.md)

For a complete catalog of failure modes and their mitigations, see [failure_modes.md](failure_modes.md).

---

## 10. Escalation Path

| Situation                              | First response                                      | Escalate to                |
| -------------------------------------- | --------------------------------------------------- | -------------------------- |
| Single investigation stuck             | Send guidance via console; skip if needed           | SSI tech lead if recurring |
| Service unresponsive (`/health` fails) | Check Cloud Run logs; redeploy if needed            | Infra lead                 |
| All investigations failing             | Check core-svc connectivity; check secrets          | SSI tech lead + Infra lead |
| eCX poller down >1 hour                | Check scheduler; manually trigger; check API key    | SSI tech lead              |
| OSINT services rate-limited            | Stagger investigations; notify analysts             | SSI tech lead              |
| Data loss / investigation lost         | Check GCS evidence bucket directly; restore from DB | Core SRE lead              |
