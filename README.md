# API Security Audit

A command-line tool that automatically scans REST APIs against the **OWASP API Security Top 10 (2023)**. It sends real HTTP requests to a target API, detects common vulnerabilities, and produces a human-readable report with plain-English explanations and remediation guidance.

---

## What it checks

| # | Category | What is tested |
|---|---|---|
| API1 | Unauthorized Data Access (BOLA) | Sequential ID probing to detect missing ownership checks |
| API2 | Broken Authentication | Access without token, access with invalid/fake token |
| API3 | Sensitive Data Leaked | PII, credentials, stack traces in responses |
| API4 | No Rate Limiting | Rapid requests without receiving a 429 block |
| API5 | Admin Endpoints Exposed | Admin paths, DELETE/PUT without authentication |
| API6 | Unprotected Business Flows | Login, registration, checkout endpoints abusable by scripts |
| API7 | Server Side Request Forgery | User-controlled URL parameters fetching internal resources |
| API8 | Security Misconfiguration | Missing security headers, wildcard CORS, SQL/NoSQL injection |
| API9 | Improper API Inventory | Old API versions still live, shadow/test endpoints in production |

> **Not covered:** API10 (Unsafe Consumption of APIs) — requires access to server-side code and cannot be tested from the outside.

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/hoxuanan91/api-security-audit.git
cd api-security-audit
pip install requests rich pyyaml click
```

---

## Usage

### With a config file (recommended)

```bash
py main.py --config examples/sample_config.yaml
```

### With command-line arguments

```bash
py main.py --url https://api.example.com --token mytoken --endpoints /users "/users/{id}" /posts
```

### Export findings to JSON

```bash
py main.py --config examples/sample_config.yaml --output report.json
```

### Disable SSL verification (for local/dev APIs)

```bash
py main.py --url https://localhost:8000 --no-ssl-verify
```

---

## Configuration file

```yaml
base_url: "https://api.example.com"

# Bearer token — leave empty for unauthenticated APIs
token: "your-token-here"

# Endpoints to scan. Use {id} to enable BOLA probing
endpoints:
  - /api/users
  - /api/users/{id}
  - /api/posts

# How many rapid requests before expecting a 429 (rate limit test)
rate_limit_threshold: 20

# ID range to probe for BOLA (API1)
bola_id_range: [1, 5]

# Request timeout in seconds
timeout: 10

# Set to false for self-signed certificates (dev only)
verify_ssl: true
```

---

## Example output

```
────────── API Security Audit — https://api.example.com ──────────
Scanned at 2026-03-18 14:32:01

┌──────┬────────────┬──────────────────────────────┬──────────────────────────────────────┐
│      │ Severity   │ Category                     │ What was detected                    │
├──────┼────────────┼──────────────────────────────┼──────────────────────────────────────┤
│ FAIL │ CRITICAL   │ Unauthorized Data Access     │ Potential BOLA — multiple sequential  │
│ FAIL │ CRITICAL   │ Missing Authentication       │ Endpoint accessible without auth      │
│ FAIL │ HIGH       │ No Rate Limiting             │ No rate limiting detected             │
│ FAIL │ HIGH       │ Security Misconfiguration    │ Missing header: Strict-Transport-...  │
└──────┴────────────┴──────────────────────────────┴──────────────────────────────────────┘

Security score: 32/100 — Critical issues found  │  2 critical  3 high  2 medium  4 passed

Understanding your findings
┌─────────────────── Unauthorized Data Access  (API1:2023) ───────────────────┐
│  What is it?                                                                │
│  Any authenticated user can access data that belongs to someone else        │
│  simply by changing an ID number in the URL...                              │
│                                                                             │
│  Real-world example                                                         │
│  You are customer #42. By changing /api/orders/42 to /api/orders/43...     │
│                                                                             │
│  How to fix                                                                 │
│    • Always verify that the authenticated user owns the requested resource  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Running tests

```bash
pip install pytest
py -m pytest tests/ -v
```

53 unit tests covering all 9 checks. All tests use mocked HTTP responses — no real network calls are made during testing.

---

## Limitations

| Limitation | Detail |
|---|---|
| **Read-only testing** | All checks use GET/POST probes only. The tool never modifies data on the target API. |
| **Heuristic-based** | Findings are based on response patterns (status codes, headers, body content). False positives are possible on APIs with non-standard behaviour. |
| **No authentication flows** | OAuth2, SAML, API key rotation and other complex auth schemes are not tested beyond basic Bearer token validation. |
| **API6 requires known paths** | Business flow protection is only tested on standard paths (/login, /register, etc.). Custom endpoint names will not be detected automatically. |
| **API9 version detection** | Only common versioning patterns (/v1, /api/v2, etc.) are probed. Non-standard versioning (headers, subdomains) is out of scope. |
| **API10 not implemented** | Unsafe consumption of third-party APIs requires server-side code access and cannot be assessed externally. |
| **Not a replacement for a pentest** | This tool is a first-pass automated scanner. A full security audit requires manual testing by a security professional. |

---

## Project structure

```
api-security-audit/
├── main.py                        # CLI entry point
├── audit/
│   ├── checks/                    # One file per OWASP check
│   │   ├── bola.py                # API1
│   │   ├── authentication.py      # API2
│   │   ├── data_exposure.py       # API3
│   │   ├── rate_limiting.py       # API4
│   │   ├── bfla.py                # API5
│   │   ├── business_flows.py      # API6
│   │   ├── ssrf.py                # API7
│   │   ├── headers.py             # API8 (headers)
│   │   ├── injection.py           # API8 (injection)
│   │   └── inventory.py           # API9
│   ├── core/
│   │   ├── scanner.py             # Orchestrates all checks
│   │   ├── report.py              # Terminal + JSON output
│   │   ├── models.py              # Finding, AuditResult, Severity
│   │   └── config.py              # ScanConfig
│   └── utils/
│       ├── http_client.py         # HTTP wrapper (requests)
│       └── patterns.py            # Regex patterns for PII/injection detection
├── tests/                         # 53 unit tests
└── examples/
    └── sample_config.yaml
```

---

## Legal

Only use this tool against APIs you own or have explicit written permission to test. Unauthorized security scanning may violate computer fraud laws in your jurisdiction.
