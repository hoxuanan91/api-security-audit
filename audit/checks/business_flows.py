"""
API6:2023 - Unrestricted Access to Sensitive Business Flows
Checks whether critical business endpoints (login, password reset, checkout,
registration, etc.) are protected against automated abuse.
Probes for missing rate limiting and missing CAPTCHA/bot-protection signals.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient

# Common sensitive business flow paths to probe
SENSITIVE_FLOW_PATHS = [
    "/login",
    "/signin",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/forgot-password",
    "/reset-password",
    "/api/password/reset",
    "/api/forgot-password",
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/api/v1/register",
    "/checkout",
    "/api/checkout",
    "/api/orders",
    "/api/payment",
    "/api/coupon/apply",
    "/api/promo",
    "/api/referral",
]

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
    "ratelimit-limit",
]

# How many rapid POST requests to send before expecting a block
ABUSE_THRESHOLD = 10


def _probe_endpoint(url: str, client: HttpClient) -> tuple[int, bool, bool]:
    """
    Returns (final_status_code, got_blocked, has_rate_limit_headers).
    Sends ABUSE_THRESHOLD POST requests and checks for 429 or rate limit headers.
    """
    got_blocked = False
    has_headers = False
    last_status = None

    for _ in range(ABUSE_THRESHOLD):
        try:
            response = client.post(url, json={"username": "test", "password": "test"})
            last_status = response.status_code
            resp_headers_lower = {k.lower() for k in response.headers}

            if any(h in resp_headers_lower for h in RATE_LIMIT_HEADERS):
                has_headers = True

            if response.status_code in (429, 423, 403):
                got_blocked = True
                break
        except Exception:
            break

    return last_status, got_blocked, has_headers


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []
    reachable_flows = []

    # Discover which sensitive flow endpoints actually exist
    for path in SENSITIVE_FLOW_PATHS:
        url = f"{config.base_url}{path}"
        try:
            response = client.post(url, json={})
            # 404/405 means the endpoint doesn't exist or doesn't accept POST
            if response.status_code not in (404, 405):
                reachable_flows.append((path, url))
        except Exception:
            pass

    if not reachable_flows:
        findings.append(Finding(
            check_id="API6:2023",
            title="No sensitive business flow endpoints detected",
            severity=Severity.INFO,
            status=Status.SKIP,
            detail=(
                f"Probed {len(SENSITIVE_FLOW_PATHS)} common sensitive paths "
                "(login, register, checkout, etc.) — none responded to POST requests."
            ),
            recommendation="Add sensitive endpoint paths to your scan config for deeper testing.",
        ))
        return findings

    for path, url in reachable_flows:
        last_status, got_blocked, has_rate_headers = _probe_endpoint(url, client)

        if got_blocked:
            findings.append(Finding(
                check_id="API6:2023",
                title=f"Business flow protected against abuse: {path}",
                severity=Severity.INFO,
                status=Status.PASS,
                detail=f"POST {url} returned a block response after repeated requests.",
                recommendation="",
            ))
        else:
            findings.append(Finding(
                check_id="API6:2023",
                title=f"Sensitive business flow unprotected against automation: {path}",
                severity=Severity.HIGH,
                status=Status.FAIL,
                detail=(
                    f"Sent {ABUSE_THRESHOLD} rapid POST requests to {url} without being blocked. "
                    f"Last status: {last_status}. This endpoint may be vulnerable to brute force, "
                    "credential stuffing, or mass registration attacks."
                ),
                recommendation=(
                    "Protect sensitive flows with rate limiting, CAPTCHA, or account lockout. "
                    "Return 429 with a Retry-After header after a threshold of failed attempts."
                ),
                evidence=f"Last status after {ABUSE_THRESHOLD} requests: {last_status}",
            ))

        if not has_rate_headers:
            findings.append(Finding(
                check_id="API6:2023",
                title=f"No rate limit headers on sensitive endpoint: {path}",
                severity=Severity.LOW,
                status=Status.WARN,
                detail=f"POST {url} never returned X-RateLimit-* or Retry-After headers.",
                recommendation="Add rate limit headers so clients know when they are being throttled.",
            ))

    return findings
