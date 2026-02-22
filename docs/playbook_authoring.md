# Playbook Authoring Guide

> **Audience:** Developers creating and testing playbooks. For a high-level overview of how playbooks work, see the [Playbooks page](../../docs/book/ssi/playbooks.md) on the docs site.

This guide explains how to create, test, and maintain JSON playbooks for the SSI playbook engine. Playbooks encode deterministic step sequences for known scam-site patterns, allowing fast, repeatable investigations without LLM reasoning for every click.

---

## Table of Contents

1. [Overview](#overview)
2. [File Location & Loading](#file-location--loading)
3. [Playbook Schema](#playbook-schema)
4. [Step Types](#step-types)
5. [Template Variables](#template-variables)
6. [URL Pattern Matching](#url-pattern-matching)
7. [Error Handling & Fallback](#error-handling--fallback)
8. [Example: Complete Playbook](#example-complete-playbook)
9. [Testing Your Playbook](#testing-your-playbook)

---

## Overview

A playbook is a JSON file describing:

- **When** to activate — a regex matched against the target URL
- **What to do** — an ordered list of browser actions (click, type, wait, extract, etc.)
- **What to fill in** — template variables (`{identity.email}`, `{password_variants.digits_8}`) resolved at runtime from a `SyntheticIdentity`

The playbook executor runs steps in order. If a step fails and `fallback_to_llm` is true, control transfers to the LLM-driven agent to continue from the current page state.

---

## File Location & Loading

Playbook files live in `config/playbooks/` as individual `.json` files:

```
config/playbooks/
├── okdc_cluster_v1.json
├── generic_crypto_exchange_v1.json
└── phishing_login_v1.json
```

At startup the `PlaybookMatcher` loads all `.json` files from this directory via `load_playbooks_from_dir()`. Files that fail validation are logged and skipped — they do not prevent other playbooks from loading.

---

## Playbook Schema

Top-level fields:

| Field              | Type     | Required | Default | Description                                              |
| ------------------ | -------- | -------- | ------- | -------------------------------------------------------- |
| `playbook_id`      | string   | Yes      | —       | Unique ID (lowercase alphanumeric + underscore)          |
| `url_pattern`      | string   | Yes      | —       | Regex to match target URLs (case-insensitive)            |
| `description`      | string   | No       | `""`    | Human-readable description                               |
| `steps`            | array    | Yes      | —       | Ordered list of `PlaybookStep` objects (min 1)           |
| `fallback_to_llm`  | boolean  | No       | `true`  | Fall back to LLM agent if the playbook fails mid-way     |
| `max_duration_sec` | integer  | No       | `120`   | Maximum wall-clock time (10–600 seconds)                 |
| `author`           | string   | No       | `""`    | Author name or team                                      |
| `version`          | string   | No       | `"1.0"` | Playbook version                                         |
| `tested_urls`      | string[] | No       | `[]`    | URLs this playbook has been validated against            |
| `tags`             | string[] | No       | `[]`    | Tags for categorisation (e.g., `"crypto"`, `"phishing"`) |
| `enabled`          | boolean  | No       | `true`  | Disabled playbooks are skipped by the matcher            |

---

## Step Types

Each step in the `steps` array is a `PlaybookStep`:

| Field              | Type    | Required | Default | Description                                             |
| ------------------ | ------- | -------- | ------- | ------------------------------------------------------- |
| `action`           | enum    | Yes      | —       | One of the step types below                             |
| `selector`         | string  | No       | `""`    | CSS selector or text content to match                   |
| `value`            | string  | No       | `""`    | Value to type, URL to navigate, seconds to wait         |
| `description`      | string  | No       | `""`    | Human-readable step description (for logs/reports)      |
| `retry_on_failure` | integer | No       | `0`     | Retry N times before considering the step failed (0–10) |
| `fallback_to_llm`  | boolean | No       | `true`  | Hand off to LLM agent if this step fails after retries  |

### Action types

| Action     | Selector            | Value               | Behaviour                                      |
| ---------- | ------------------- | ------------------- | ---------------------------------------------- |
| `click`    | CSS or visible text | —                   | Click the element matching the selector        |
| `type`     | CSS selector        | Text to enter       | Clear the field and type the value             |
| `select`   | CSS selector        | Option value/text   | Select a dropdown option                       |
| `navigate` | —                   | URL                 | Navigate to the specified URL                  |
| `wait`     | —                   | Seconds (as string) | Wait for the specified number of seconds       |
| `scroll`   | —                   | Pixels (as string)  | Scroll down by the specified number of pixels  |
| `extract`  | —                   | —                   | Extract wallet addresses from the current page |

### Selector resolution

For `click` steps the selector can be:

- A **CSS selector**: `"[name='email']"`, `"#submit-btn"`, `".deposit-tab"`
- **Visible text**: `"Sign Up"`, `"Deposit"`, `"BTC"` — the executor searches for elements whose visible text matches

For `type` and `select` steps, use CSS selectors. Comma-separated selectors try each one in order:

```json
"selector": "[name='email'], [placeholder*='email'], #email"
```

---

## Template Variables

Step `value` fields support template variables enclosed in `{…}`. These are resolved at runtime from the `SyntheticIdentity` generated by the identity vault.

### Supported namespaces

| Namespace                       | Example                        | Resolves to                      |
| ------------------------------- | ------------------------------ | -------------------------------- |
| `{identity.<field>}`            | `{identity.email}`             | Synthetic identity email address |
| `{password_variants.<variant>}` | `{password_variants.digits_8}` | An 8-digit numeric password      |
| `{<field>}`                     | `{email}`                      | Shorthand for `{identity.email}` |

### Common identity fields

- `{identity.email}` — synthetic email address
- `{identity.password}` — primary password
- `{identity.first_name}`, `{identity.last_name}` — synthetic name
- `{identity.phone}` — synthetic phone number
- `{identity.address}` — synthetic street address

### Password variants

Use these when sites have specific password requirements:

- `{password_variants.digits_8}` — 8 random digits
- `{password_variants.alphanumeric_8}` — 8 alphanumeric characters
- `{password_variants.complex_12}` — 12-char password with special characters

Unresolved placeholders are left as-is and logged as warnings.

---

## URL Pattern Matching

The `url_pattern` field is a Python regex matched case-insensitively against the full target URL. The first playbook whose pattern matches wins.

```json
// Matches any URL containing "okdc", "ok-dc", or "okexchange"
"url_pattern": "okdc|ok-dc|okx.*clone|okexchange"

// Matches common phishing login page patterns
"url_pattern": "(login|signin|verify|secure|account).*\\.(com|net|org|io|xyz|top|click)"
```

> **Tip**: Keep patterns specific enough to avoid false matches. Test with `re.search(pattern, url, re.IGNORECASE)` in a Python REPL.

---

## Error Handling & Fallback

The playbook engine handles failures at two levels:

### Step-level

Each step can declare `retry_on_failure` (0–10). On failure, the step retries with a short delay. If all retries are exhausted and `fallback_to_llm` is `true`, control passes to the LLM agent to continue from the current browser state.

### Playbook-level

If the entire playbook declares `fallback_to_llm: true` and fails mid-way, the orchestrator switches to LLM-driven analysis from the current page. The `PlaybookResult` records which steps succeeded, which failed, and whether LLM fallback was triggered.

### Time budget

`max_duration_sec` enforces a wall-clock time limit (10–600 seconds). If the playbook exceeds this, remaining steps are skipped and `fallback_to_llm` applies.

---

## Example: Complete Playbook

A minimal playbook for a phishing login page:

```json
{
  "playbook_id": "phishing_login_v1",
  "url_pattern": "(login|signin|verify).*\\.(xyz|top|click)",
  "description": "Generic phishing login — enter credentials, observe redirect.",
  "steps": [
    {
      "action": "type",
      "selector": "[name='email'], [type='email'], #email",
      "value": "{identity.email}",
      "description": "Enter synthetic email.",
      "retry_on_failure": 2,
      "fallback_to_llm": true
    },
    {
      "action": "type",
      "selector": "[name='password'], [type='password'], #password",
      "value": "{identity.password}",
      "description": "Enter synthetic password.",
      "retry_on_failure": 1
    },
    {
      "action": "click",
      "selector": "Log In",
      "description": "Submit the login form.",
      "retry_on_failure": 2,
      "fallback_to_llm": true
    },
    {
      "action": "wait",
      "value": "4",
      "description": "Wait for redirect or follow-up page."
    },
    {
      "action": "extract",
      "description": "Extract wallet addresses from post-login page."
    }
  ],
  "fallback_to_llm": true,
  "max_duration_sec": 60,
  "author": "ssi-team",
  "version": "1.0",
  "tags": ["phishing", "login"],
  "tested_urls": [],
  "enabled": true
}
```

Save this as `config/playbooks/phishing_login_v1.json`.

---

## Testing Your Playbook

### 1. Validate the JSON schema

```bash
conda run -n i4g-ssi python -c "
from ssi.playbook.loader import load_playbook_from_file
from pathlib import Path
pb = load_playbook_from_file(Path('config/playbooks/your_playbook.json'))
print(f'Loaded: {pb.playbook_id} ({len(pb.steps)} steps)')
"
```

### 2. Test URL matching

```bash
conda run -n i4g-ssi python -c "
import re
pattern = 'your_url_pattern_here'
url = 'https://example-scam-site.com/login'
print('Match' if re.search(pattern, url, re.IGNORECASE) else 'No match')
"
```

### 3. Run a CLI investigation against a test URL

```bash
conda run -n i4g-ssi ssi investigate url "https://your-test-url.com" --passive
```

### 4. Run integration tests

```bash
conda run -n i4g-ssi pytest tests/integration/ -v -k playbook
```

### Checklist before merging

- [ ] `playbook_id` is lowercase, unique, ends with `_v<N>`
- [ ] `url_pattern` compiles as a valid regex
- [ ] At least one step has `action: "extract"` to capture wallet addresses
- [ ] `tested_urls` lists at least one URL this was validated against
- [ ] `description` is a single sentence summarising the scam flow
- [ ] `tags` include the relevant scam category
