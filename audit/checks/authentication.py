"""
API2:2023 - Broken Authentication
Checks whether endpoints are properly protected by authentication.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    for endpoint in config.endpoints:
        url = f"{config.base_url}{endpoint}"

        # Test 1: request with no auth token at all
        try:
            response = client.request_without_auth("GET", url)
            if response.status_code < 400:
                findings.append(Finding(
                    check_id="API2:2023",
                    title="Endpoint accessible without authentication",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    detail=f"GET {url} returned {response.status_code} with no Authorization header.",
                    recommendation="Enforce authentication on all non-public endpoints. Return 401 for missing credentials.",
                    evidence=f"Status: {response.status_code}",
                ))
            else:
                findings.append(Finding(
                    check_id="API2:2023",
                    title="Authentication enforced",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    detail=f"GET {url} correctly returned {response.status_code} without auth.",
                    recommendation="",
                ))
        except Exception as e:
            findings.append(Finding(
                check_id="API2:2023",
                title="Authentication check error",
                severity=Severity.LOW,
                status=Status.SKIP,
                detail=f"Could not reach {url}: {e}",
                recommendation="Ensure the target is reachable.",
            ))

        # Test 2: request with a clearly invalid/malformed token
        try:
            response = client.request_without_auth(
                "GET", url, headers={"Authorization": "Bearer invalid.token.value"}
            )
            if response.status_code < 400:
                findings.append(Finding(
                    check_id="API2:2023",
                    title="Endpoint accepts invalid token",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    detail=f"GET {url} returned {response.status_code} with a clearly invalid Bearer token.",
                    recommendation="Validate token signature and expiry on every request. Never trust malformed tokens.",
                    evidence=f"Status: {response.status_code}",
                ))
        except Exception:
            pass

    return findings
