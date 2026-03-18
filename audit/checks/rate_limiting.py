"""
API4:2023 - Unrestricted Resource Consumption
Checks whether the API enforces rate limiting.
"""
import time
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
    "ratelimit-limit",
]


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    if not config.endpoints:
        return findings

    endpoint = config.endpoints[0]
    url = f"{config.base_url}{endpoint}"
    threshold = config.rate_limit_threshold

    got_429 = False
    has_rate_limit_headers = False
    last_status = None

    for i in range(threshold):
        try:
            response = client.get(url)
            last_status = response.status_code
            response_headers_lower = {k.lower() for k in response.headers}

            if any(h in response_headers_lower for h in RATE_LIMIT_HEADERS):
                has_rate_limit_headers = True

            if response.status_code == 429:
                got_429 = True
                break
        except Exception as e:
            findings.append(Finding(
                check_id="API4:2023",
                title="Rate limiting check failed",
                severity=Severity.LOW,
                status=Status.SKIP,
                detail=str(e),
                recommendation="Ensure the endpoint is reachable.",
            ))
            return findings

    if got_429:
        findings.append(Finding(
            check_id="API4:2023",
            title="Rate limiting enforced (429 received)",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=f"Server returned 429 after {i + 1} rapid requests to {url}.",
            recommendation="",
        ))
    else:
        findings.append(Finding(
            check_id="API4:2023",
            title="No rate limiting detected",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail=f"Sent {threshold} rapid requests to {url} without receiving a 429. Last status: {last_status}.",
            recommendation="Implement rate limiting per IP and/or per token. Return 429 with Retry-After header.",
        ))

    if has_rate_limit_headers:
        findings.append(Finding(
            check_id="API4:2023",
            title="Rate limit headers present",
            severity=Severity.INFO,
            status=Status.PASS,
            detail="Response includes rate limit headers (X-RateLimit-*).",
            recommendation="",
        ))
    else:
        findings.append(Finding(
            check_id="API4:2023",
            title="Rate limit headers missing",
            severity=Severity.LOW,
            status=Status.WARN,
            detail="No standard rate limit headers found in response.",
            recommendation="Add X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.",
        ))

    return findings
