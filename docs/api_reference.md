# SSI API Reference

REST API endpoints exposed by the SSI FastAPI server (default: `http://localhost:8100`).

---

## Endpoints

### `GET /health`

Health check.

**Response** `200 OK`:

```json
{ "status": "ok" }
```

---

### `POST /investigate`

Submit a URL for investigation. Returns immediately with a task ID.

**Request body**:

| Field             | Type    | Required | Default     | Description                              |
| ----------------- | ------- | -------- | ----------- | ---------------------------------------- |
| `url`             | string  | Yes      | —           | The suspicious URL to investigate        |
| `scan_type`       | string  | No       | `"passive"` | `passive`, `active`, or `full`           |
| `skip_whois`      | boolean | No       | `false`     | Skip WHOIS/RDAP lookup                   |
| `skip_screenshot` | boolean | No       | `false`     | Skip screenshot capture                  |
| `skip_virustotal` | boolean | No       | `false`     | Skip VirusTotal check                    |
| `push_to_core`    | boolean | No       | `false`     | Push results to i4g core platform        |
| `trigger_dossier` | boolean | No       | `false`     | Queue dossier generation after core push |
| `dataset`         | string  | No       | `"ssi"`     | Dataset label for the core case          |

**Example request**:

```bash
curl -X POST http://localhost:8100/investigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com", "scan_type": "passive"}'
```

**Response** `200 OK`:

```json
{
  "investigation_id": "a1b2c3d4-...",
  "status": "pending",
  "message": "Investigation queued. Poll /investigate/{id} for status."
}
```

**Response** `429 Too Many Requests`:

```json
{
  "detail": "Server is at capacity (5 concurrent investigations). Try again later."
}
```

Returned when the concurrent investigation limit is reached. Configure via `SSI_API__MAX_CONCURRENT_INVESTIGATIONS` (default: 5).

**Response** `422 Validation Error`:

Returned for invalid `scan_type` values or missing required fields.

---

### `GET /investigate/{investigation_id}`

Check the status of a previously submitted investigation.

**Path parameters**:

| Parameter          | Type   | Description                |
| ------------------ | ------ | -------------------------- |
| `investigation_id` | string | Task ID from the POST call |

**Response** `200 OK` (pending):

```json
{
  "investigation_id": "a1b2c3d4-...",
  "status": "pending",
  "result": null
}
```

**Response** `200 OK` (completed):

```json
{
  "investigation_id": "a1b2c3d4-...",
  "status": "completed",
  "result": {
    "url": "https://suspicious-site.com",
    "risk_score": 85,
    "classification": { ... },
    "wallet_addresses": [ ... ],
    "whois": { ... },
    "dns": { ... },
    "ssl": { ... }
  }
}
```

**Response** `200 OK` (failed):

```json
{
  "investigation_id": "a1b2c3d4-...",
  "status": "failed",
  "result": {
    "error": "Investigation failed"
  }
}
```

> Error details are intentionally generic. Internal details are logged server-side but never exposed in API responses (see [Hardening & Resilience](developer_guide.md#14-hardening--resilience)).

**Response** `404 Not Found`:

```json
{
  "detail": "Investigation not found."
}
```

---

## Web UI Routes

These routes serve the built-in Jinja2 web interface and are not part of the JSON API.

| Route               | Method | Description                    |
| ------------------- | ------ | ------------------------------ |
| `/`                 | GET    | Investigation submission form  |
| `/status/{task_id}` | GET    | Results page with PDF download |

---

## Status Values

| Status      | Description                                                             |
| ----------- | ----------------------------------------------------------------------- |
| `pending`   | Investigation queued, not yet started                                   |
| `running`   | Investigation in progress                                               |
| `completed` | Investigation finished (may include partial results if budget exceeded) |
| `failed`    | Investigation failed due to an unrecoverable error                      |

---

## Rate Limiting & Concurrency

- **Concurrent investigation limit**: Controlled by `SSI_API__MAX_CONCURRENT_INVESTIGATIONS` (default: 5). When all slots are occupied, `POST /investigate` returns HTTP 429.
- **Cost budget**: Each investigation has an independent cost budget. If exceeded, the investigation completes with partial results rather than failing.
- Clients submitting batch workloads should implement retry-with-backoff for 429 responses.

---

## Authentication

The SSI API does not require authentication. In production, it runs behind IAP (Identity-Aware Proxy) on Cloud Run. The `/ssi` route on the i4g console (`ui/`) is public and proxies to the SSI API.
