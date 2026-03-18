"""
API3:2023 - Broken Object Property Level Authorization
Checks whether API responses leak sensitive data (PII, secrets, stack traces).
"""
import json
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient
from audit.utils.patterns import PATTERNS


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    for endpoint in config.endpoints:
        url = f"{config.base_url}{endpoint}"
        try:
            response = client.get(url)
            body = response.text
        except Exception as e:
            findings.append(Finding(
                check_id="API3:2023",
                title="Data exposure check failed",
                severity=Severity.LOW,
                status=Status.SKIP,
                detail=str(e),
                recommendation="Ensure the endpoint is reachable.",
            ))
            continue

        # Check for PII patterns in response body
        for pattern_name, pattern in PATTERNS.items():
            match = pattern.search(body)
            if match:
                severity_map = {
                    "credit_card": Severity.CRITICAL,
                    "ssn_fr": Severity.CRITICAL,
                    "iban": Severity.CRITICAL,
                    "jwt": Severity.HIGH,
                    "api_key": Severity.HIGH,
                    "stack_trace": Severity.HIGH,
                    "internal_path": Severity.MEDIUM,
                    "email": Severity.MEDIUM,
                    "phone_fr": Severity.MEDIUM,
                    "phone_intl": Severity.MEDIUM,
                }
                findings.append(Finding(
                    check_id="API3:2023",
                    title=f"Sensitive data exposed: {pattern_name}",
                    severity=severity_map.get(pattern_name, Severity.MEDIUM),
                    status=Status.FAIL,
                    detail=f"Pattern '{pattern_name}' matched in response from {url}.",
                    recommendation="Strip sensitive fields from API responses. Apply field-level access control.",
                    evidence=f"Matched: {match.group(0)[:40]}...",
                ))

        # Check for verbose error responses (stack traces, internal paths)
        try:
            error_response = client.get(f"{url}/nonexistent_path_xyz")
            if error_response.status_code >= 500:
                error_body = error_response.text
                if PATTERNS["stack_trace"].search(error_body) or PATTERNS["internal_path"].search(error_body):
                    findings.append(Finding(
                        check_id="API3:2023",
                        title="Verbose error response exposes internals",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        detail=f"Server error at {url} contains stack trace or internal paths.",
                        recommendation="Use generic error messages in production. Log details server-side only.",
                        evidence=f"Status {error_response.status_code} with internal details",
                    ))
        except Exception:
            pass

        # Check for excessive data: large number of fields returned
        try:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                field_count = len(data[0]) if isinstance(data[0], dict) else 0
                if field_count > 20:
                    findings.append(Finding(
                        check_id="API3:2023",
                        title="Response may expose excessive fields",
                        severity=Severity.LOW,
                        status=Status.WARN,
                        detail=f"{url} returns objects with {field_count} fields. Review if all are needed by the client.",
                        recommendation="Apply response filtering. Only return fields the consumer actually needs.",
                    ))
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return findings
