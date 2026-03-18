"""
API8:2023 - Security Misconfiguration
Checks for missing or misconfigured security headers and CORS policy.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient
from audit.utils.patterns import SECURITY_HEADERS


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []
    url = config.base_url

    try:
        response = client.get(url)
        headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception as e:
        findings.append(Finding(
            check_id="API8:2023",
            title="Security headers check failed",
            severity=Severity.LOW,
            status=Status.SKIP,
            detail=str(e),
            recommendation="Ensure the base URL is reachable.",
        ))
        return findings

    # Check each expected security header
    for header, description in SECURITY_HEADERS.items():
        if header.lower() in headers:
            findings.append(Finding(
                check_id="API8:2023",
                title=f"Header present: {header}",
                severity=Severity.INFO,
                status=Status.PASS,
                detail=f"{header}: {headers[header.lower()]}",
                recommendation="",
            ))
        else:
            severity = Severity.HIGH if header in ("Strict-Transport-Security", "Content-Security-Policy") else Severity.MEDIUM
            findings.append(Finding(
                check_id="API8:2023",
                title=f"Missing security header: {header}",
                severity=severity,
                status=Status.FAIL,
                detail=f"The response does not include '{header}' ({description}).",
                recommendation=f"Add the '{header}' header to all API responses.",
            ))

    # CORS check: wildcard origin is dangerous on authenticated APIs
    cors_header = headers.get("access-control-allow-origin", "")
    if cors_header == "*":
        findings.append(Finding(
            check_id="API8:2023",
            title="Wildcard CORS policy detected",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="Access-Control-Allow-Origin: * allows any origin to make cross-site requests.",
            recommendation="Restrict CORS to trusted domains. Never use '*' on authenticated APIs.",
            evidence=f"Access-Control-Allow-Origin: {cors_header}",
        ))

    return findings
