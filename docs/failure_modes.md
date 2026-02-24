# SSI Failure Modes Catalog

> **Task 1.5** — Phase 1, Local Testing & Validation. This document catalogs
> known failure modes that the investigation pipeline may encounter, their root
> causes, detection heuristics, and recommended mitigations.

## Purpose

Scam sites employ a wide variety of anti-analysis techniques. This catalog
tracks every known category of failure so that:

1. **Regression tests** can target specific failure modes.
2. **Operators** can triage partial-result investigations quickly.
3. **Priority backlog** items are justified by quantified failure rates.

---

## Failure Mode Categories

### FM-01: CAPTCHA Blocks

| Field          | Value                                                                       |
| -------------- | --------------------------------------------------------------------------- |
| **Trigger**    | reCAPTCHA, hCaptcha, Cloudflare Turnstile, custom                           |
| **Detection**  | `detect_captcha()` returns `detected=True`                                  |
| **Impact**     | Active agent cannot proceed past CAPTCHA gate                               |
| **Mitigation** | SKIP (partial), WAIT (Turnstile), ACCESSIBILITY                             |
| **Fixture**    | `captcha_recaptcha.html`, `captcha_hcaptcha.html`, `captcha_turnstile.html` |
| **Test**       | `tests/unit/test_captcha_detection.py`                                      |

### FM-02: Anti-Bot / Browser Fingerprinting

| Field          | Value                                                       |
| -------------- | ----------------------------------------------------------- |
| **Trigger**    | Bot-detection JS (Akamai, PerimeterX, Imperva, DataDome)    |
| **Detection**  | HTTP 403/429, blank page body, "Access Denied" text         |
| **Impact**     | Page content unavailable; screenshot blank                  |
| **Mitigation** | Stealth browser flags, realistic user-agent, proxy rotation |
| **Fixture**    | _TBD — Phase 2 anti-bot fixture_                            |
| **Test**       | _Planned_                                                   |

### FM-03: Geo-Fenced Content

| Field          | Value                                                              |
| -------------- | ------------------------------------------------------------------ |
| **Trigger**    | Site serves different content based on IP geolocation              |
| **Detection**  | HTTP 302 redirect to region-specific domain, or empty scam content |
| **Impact**     | Classification may miss scam indicators; wallets unreachable       |
| **Mitigation** | Proxy with target-country exit; re-run from multiple geos          |
| **Fixture**    | _TBD — Phase 2 geo-fencing fixture_                                |
| **Test**       | _Planned_                                                          |

### FM-04: Heavy JavaScript SPA

| Field          | Value                                                            |
| -------------- | ---------------------------------------------------------------- |
| **Trigger**    | React/Vue/Angular SPA with lazy-loaded scam content              |
| **Detection**  | DOM snapshot has minimal content; `<noscript>` present           |
| **Impact**     | Text extraction and wallet scanning miss dynamic content         |
| **Mitigation** | Playwright `wait_for_load_state("networkidle")`, scroll triggers |
| **Fixture**    | _TBD — Phase 2 SPA fixture_                                      |
| **Test**       | _Planned_                                                        |

### FM-05: Domain Takedown / Parked

| Field          | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| **Trigger**    | Domain already seized by registrar, suspended, or parked      |
| **Detection**  | DNS NXDOMAIN, HTTP 404/503, parking page text                 |
| **Impact**     | Investigation returns "domain not resolvable"                 |
| **Mitigation** | Check Wayback Machine; record finding for historical analysis |
| **Fixture**    | Simulated by `_check_domain_resolution` returning False       |
| **Test**       | `tests/integration/test_e2e_pipeline.py` (planned)            |

### FM-06: Rate Limiting / IP Blocks

| Field          | Value                                                              |
| -------------- | ------------------------------------------------------------------ |
| **Trigger**    | Too many requests from same IP; Cloudflare rate-limit              |
| **Detection**  | HTTP 429, "Too Many Requests", connection timeouts                 |
| **Impact**     | OSINT lookups fail; browser capture blocked                        |
| **Mitigation** | `@with_retries` decorator with exponential backoff; proxy rotation |
| **Fixture**    | _Simulated via mock returning HTTP 429_                            |
| **Test**       | `tests/unit/test_phase8b_hardening.py`                             |

### FM-07: SSL/TLS Errors

| Field          | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| **Trigger**    | Self-signed cert, expired cert, cert mismatch                 |
| **Detection**  | SSL handshake failure; Playwright `ERR_CERT_*`                |
| **Impact**     | Browser capture fails; SSL info incomplete                    |
| **Mitigation** | `ignore_https_errors=True` for investigation; log SSL warning |
| **Fixture**    | Simulated via `_FAKE_SSL` with `is_self_signed=True`          |
| **Test**       | _Planned_                                                     |

### FM-08: OSINT Service Downtime

| Field          | Value                                               |
| -------------- | --------------------------------------------------- |
| **Trigger**    | VirusTotal / urlscan / WHOIS service unavailable    |
| **Detection**  | HTTP 5xx, connection timeout, DNS failure           |
| **Impact**     | Partial OSINT results; threat indicators incomplete |
| **Mitigation** | Retry with backoff; skip and note in warnings list  |
| **Fixture**    | Mocked by patching OSINT call to raise `Exception`  |
| **Test**       | `tests/integration/test_e2e_pipeline.py`            |

### FM-09: LLM Provider Errors

| Field          | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| **Trigger**    | API quota exhausted, model unavailable, timeout               |
| **Detection**  | `check_connectivity()` returns False; HTTP 429/503            |
| **Impact**     | Classification and agent interaction cannot proceed           |
| **Mitigation** | `RetryingLLMProvider`; fallback to passive-only mode          |
| **Fixture**    | `mock_llm_provider` fixture with configurable errors          |
| **Test**       | `tests/unit/test_llm_client.py`, `test_dual_model_routing.py` |

### FM-10: Wallet Address Obfuscation

| Field          | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| **Trigger**    | Address split across elements, encoded in JS, in image/QR     |
| **Detection**  | `_extract_wallets` finds fewer wallets than expected          |
| **Impact**     | Wallet harvest incomplete; intelligence gap                   |
| **Mitigation** | QR scanning, agent clipboard extraction, LLM-assisted reading |
| **Fixture**    | `deposit.html` (explicit), `pig_butchering.html` (scattered)  |
| **Test**       | `tests/unit/test_wallet.py`                                   |

---

## Tracking Matrix

| FM ID | Category           | Test Coverage | Fixture | Phase |
| ----- | ------------------ | ------------- | ------- | ----- |
| FM-01 | CAPTCHA            | ✅ Unit       | ✅      | 1     |
| FM-02 | Anti-Bot           | ❌            | ❌      | 2     |
| FM-03 | Geo-Fencing        | ❌            | ❌      | 2     |
| FM-04 | Heavy JS SPA       | ❌            | ❌      | 2     |
| FM-05 | Domain Takedown    | ⚠️ Partial    | ⚠️ Mock | 1     |
| FM-06 | Rate Limiting      | ✅ Unit       | ⚠️ Mock | 1     |
| FM-07 | SSL Errors         | ❌            | ⚠️ Mock | 2     |
| FM-08 | OSINT Downtime     | ⚠️ Partial    | ⚠️ Mock | 1     |
| FM-09 | LLM Errors         | ✅ Unit       | ✅ Mock | 1     |
| FM-10 | Wallet Obfuscation | ⚠️ Partial    | ✅      | 1-2   |

---

## Adding a New Failure Mode

1. **Create entry** — add a `FM-XX` section to this document following the table format.
2. **Create fixture** — add an HTML file to `tests/fixtures/scam_sites/` that exhibits the failure mode.
3. **Write test** — add a test case in the appropriate unit or integration test file.
4. **Update matrix** — mark coverage status in the tracking matrix.
5. **Update batch manifest** — if the fixture represents a new scam type, add it to `tests/fixtures/batch_manifest.json`.
