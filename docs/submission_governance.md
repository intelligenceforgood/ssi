# eCrimeX Submission Governance

This document covers how SSI routes investigation findings to the
[APWG eCrimeX](https://ecrimex.net/) data clearinghouse, the safety gates
that prevent accidental data transmission, and the analyst workflow for
reviewing queued submissions.

---

## Safety Gates

Two independent flags **both** must be `true` before any indicator data
leaves SSI. A single misconfiguration cannot trigger live submissions.

| Environment variable                   | Default | Purpose                                                                                    |
| -------------------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| `SSI_ECX__SUBMISSION_ENABLED`          | `false` | Master on/off switch for Phase 2 submission.                                               |
| `SSI_ECX__SUBMISSION_AGREEMENT_SIGNED` | `false` | Confirms the APWG data-sharing agreement has been executed. Set only after legal sign-off. |

Set both in `.env.local` (local) or Secret Manager (cloud) when you are
ready to submit:

```
SSI_ECX__SUBMISSION_ENABLED=true
SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true
```

> **Never commit these values to source control.** Use the platform secret
> manager or `.env.local` (which is git-ignored).

---

## Confidence Thresholds

After an investigation completes, `ECXSubmissionService.process_investigation()`
scores each indicator and routes it based on two configurable thresholds.

| Setting                 | Env var                          | Default | Behaviour                                                                                         |
| ----------------------- | -------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `auto_submit_threshold` | `SSI_ECX__AUTO_SUBMIT_THRESHOLD` | `80`    | Indicators at or above this confidence are submitted immediately without analyst review.          |
| `queue_threshold`       | `SSI_ECX__QUEUE_THRESHOLD`       | `50`    | Indicators between `queue_threshold` and `auto_submit_threshold` are queued for analyst approval. |

Indicators below `queue_threshold` are silently skipped.

```
confidence ≥ 80  →  auto-submit  (status: "submitted")
50 ≤ confidence < 80  →  queue  (status: "queued")
confidence < 50  →  skip
```

Tune these values via environment overrides without touching code.

---

## eCX Module Field Mapping

Each indicator type maps to a specific eCX API module.

| Indicator        | eCX module                 | Primary field | Extra fields                            |
| ---------------- | -------------------------- | ------------- | --------------------------------------- |
| Phishing URL     | `phish`                    | `url`         | `brand`, `ip`                           |
| Malicious domain | `malicious-domain`         | `domain`      | `classification`                        |
| Malicious IP     | `malicious-ip`             | `ip`          | `description`                           |
| Crypto address   | `cryptocurrency-addresses` | `address`     | `currency`, `crimeCategory`, `siteLink` |

The `release_label` (e.g. `WHITE`, `GREEN`, `AMBER`) is set at approval
time by the analyst and controls how eCX distributes the record to
consortium members.

---

## Submission Lifecycle

```
Investigation completes
        │
        ▼
process_investigation()
        │
        ├── confidence ≥ auto_threshold ──► _auto_submit()
        │                                        │
        │                                        ▼
        │                                   eCX API  (status: "submitted")
        │
        ├── queue_threshold ≤ conf < auto ──► _queue_for_review()
        │                                        │
        │                                        ▼
        │                              ScanStore  (status: "queued")
        │                                        │
        │                                   Analyst reviews
        │                                   /           \
        │                         approve()             reject()
        │                              │                    │
        │                         eCX API             local only
        │                    (status: "submitted")  (status: "rejected")
        │
        └── confidence < queue_threshold ──► skip
```

### Deduplication

Before creating a new eCX record, `_submit_with_dedup()` searches eCX for
an existing record matching the same indicator value. If one is found, it
calls `update_record()` to refresh the confidence rather than creating a
duplicate. Both the original and the duplicate submission rows share the
same `ecx_record_id`.

---

## Analyst Approval Workflow

Queued submissions are reviewed in the analyst console at
`/ssi/submissions` or on the investigation detail page (Results tab →
eCrimeX Submissions).

### Single-record actions

| Action  | Endpoint                             | Effect                                                                   |
| ------- | ------------------------------------ | ------------------------------------------------------------------------ |
| Approve | `POST /ecx/submissions/{id}/approve` | Transmits to eCX; status becomes `submitted`.                            |
| Reject  | `POST /ecx/submissions/{id}/reject`  | Marks rejected locally; nothing sent to eCX.                             |
| Retract | `POST /ecx/submissions/{id}/retract` | Calls eCX `update_record(status="removed")`; status becomes `retracted`. |

### Bulk actions (Submissions Queue page)

Select one or more queued rows, enter an analyst ID, and click
**Bulk Approve** or **Bulk Reject**. Actions run in parallel via
`Promise.allSettled`; partial failures are reported per row without
blocking the batch.

---

## Retraction Flow

Retracting a submitted record:

1. Calls `ECXClient.update_record(module, ecx_record_id, status="removed")`.
2. Marks the local submission row `"retracted"`.
3. If the eCX API call fails, the local row is still marked `"retracted"` and
   the error is stored in `error_message` for audit.

Only records with `status == "submitted"` can be retracted. Queued or
rejected records should be rejected locally — they were never sent to eCX.

---

## Environment Variable Reference

| Variable                               | Default                                   | Description                                            |
| -------------------------------------- | ----------------------------------------- | ------------------------------------------------------ |
| `SSI_ECX__ENABLED`                     | `false`                                   | Enable Phase 1 enrichment queries.                     |
| `SSI_ECX__ENRICHMENT_ENABLED`          | `true`                                    | Enable eCX enrichment within investigations.           |
| `SSI_ECX__SUBMISSION_ENABLED`          | `false`                                   | Enable Phase 2 submission (safety gate 1).             |
| `SSI_ECX__SUBMISSION_AGREEMENT_SIGNED` | `false`                                   | Confirm APWG agreement (safety gate 2).                |
| `SSI_ECX__AUTO_SUBMIT_THRESHOLD`       | `80`                                      | Confidence threshold for auto-submission.              |
| `SSI_ECX__QUEUE_THRESHOLD`             | `50`                                      | Confidence threshold for analyst queue.                |
| `SSI_ECX__API_KEY`                     | ``                                        | eCrimeX API key.                                       |
| `SSI_ECX__BASE_URL`                    | `https://sandbox.ecx2.ecrimex.net/api/v1` | eCX API base URL. Switch to production URL when ready. |
| `SSI_ECX__ATTRIBUTION`                 | `IntelligenceForGood`                     | Attribution string attached to submitted records.      |
| `SSI_ECX__TIMEOUT`                     | `15`                                      | HTTP client timeout (seconds).                         |
| `SSI_ECX__CACHE_TTL_HOURS`             | `24`                                      | Enrichment cache TTL.                                  |

---

## Enabling Submissions: Step-by-Step

1. **Execute the APWG data-sharing agreement** with your legal team.
2. Obtain a production eCX API key from APWG.
3. Update `SSI_ECX__BASE_URL` to the production endpoint.
4. Store API key in Secret Manager (cloud) or `.env.local` (local).
5. Set `SSI_ECX__SUBMISSION_ENABLED=true` and
   `SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true`.
6. Deploy the updated Cloud Run job / local service.
7. Run the sandbox integration tests (see [Testing](#testing)) against the
   production endpoint to confirm connectivity before submitting real data.

---

## Testing

### Unit tests

```bash
conda run -n i4g-ssi pytest tests/unit/ecx/ -v
```

### Sandbox integration tests (enrichment only)

```bash
SSI_ECX__API_KEY="your-sandbox-key" \
  conda run -n i4g-ssi pytest tests/integration/test_ecx_sandbox.py -v
```

### Sandbox integration tests (with submission)

Requires a sandbox key that has write access:

```bash
SSI_ECX__API_KEY="your-sandbox-key" \
SSI_ECX__SUBMISSION_ENABLED=true \
SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true \
  conda run -n i4g-ssi pytest \
    tests/integration/test_ecx_sandbox.py::TestECXSubmissionSandbox -v
```

---

## Related Files

| File                                                                                | Purpose                                   |
| ----------------------------------------------------------------------------------- | ----------------------------------------- |
| [`src/ssi/ecx/submission.py`](../src/ssi/ecx/submission.py)                         | `ECXSubmissionService` — governance logic |
| [`src/ssi/osint/ecrimex.py`](../src/ssi/osint/ecrimex.py)                           | `ECXClient` — API transport               |
| [`src/ssi/api/ecx_routes.py`](../src/ssi/api/ecx_routes.py)                         | FastAPI endpoints for submission CRUD     |
| [`src/ssi/store/scan_store.py`](../src/ssi/store/scan_store.py)                     | `create/update/get/list_ecx_submission`   |
| [`config/settings.default.toml`](../config/settings.default.toml)                   | Default settings including thresholds     |
| [`tests/integration/test_ecx_sandbox.py`](../tests/integration/test_ecx_sandbox.py) | Sandbox integration test suite            |
