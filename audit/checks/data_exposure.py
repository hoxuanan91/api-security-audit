"""
API3:2023 - Broken Object Property Level Authorization
Checks whether API responses leak sensitive data (PII, secrets, stack traces).
"""
import json
import re
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient
from audit.utils.patterns import PATTERNS

# Human-readable description for each pattern type
PATTERN_DESCRIPTIONS = {
    "credit_card":    "Credit card number",
    "ssn_fr":         "French social security number (Numéro de sécurité sociale)",
    "iban":           "Bank account number (IBAN)",
    "jwt":            "Authentication token (JWT)",
    "api_key":        "API key or secret",
    "stack_trace":    "Application stack trace (internal error detail)",
    "internal_path":  "Internal server file path",
    "email":          "Email address",
    "phone_fr":       "French phone number",
    "phone_intl":     "International phone number",
}


def _mask(value: str, pattern_name: str) -> str:
    """Return a masked version of the matched value safe to display in a report."""
    v = value.strip()
    if pattern_name == "credit_card":
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 8:
            return digits[:4] + " **** **** " + digits[-4:]
        return "*" * len(v)
    if pattern_name in ("ssn_fr", "iban"):
        return v[:4] + "*" * max(0, len(v) - 8) + v[-4:] if len(v) > 8 else "*" * len(v)
    if pattern_name == "jwt":
        return v[:20] + "...[truncated]"
    if pattern_name == "api_key":
        # Show key name but mask the value part
        eq = v.find("=") + 1 or v.find(":") + 1
        prefix = v[:eq] if eq else ""
        secret = v[eq:]
        return prefix + secret[:4] + "*" * min(12, len(secret) - 4)
    # For less sensitive types show as-is
    return v[:60]


def _surrounding_context(body: str, match, chars: int = 60) -> str:
    """Return a snippet of the response body around the match position."""
    start = max(0, match.start() - chars)
    end = min(len(body), match.end() + chars)
    snippet = body[start:end].replace("\n", " ").replace("\r", "")
    if start > 0:
        snippet = "..." + snippet
    if end < len(body):
        snippet = snippet + "..."
    return snippet


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

                all_matches = pattern.findall(body)
                count = len(all_matches)
                description = PATTERN_DESCRIPTIONS.get(pattern_name, pattern_name)
                masked = _mask(match.group(0), pattern_name)
                context = _surrounding_context(body, match)

                findings.append(Finding(
                    check_id="API3:2023",
                    title=f"Sensitive data exposed: {description}",
                    severity=severity_map.get(pattern_name, Severity.MEDIUM),
                    status=Status.FAIL,
                    detail=(
                        f"{count} occurrence(s) of {description} detected in the response from {url}. "
                        f"Example value: {masked}"
                    ),
                    recommendation="Strip sensitive fields from API responses. Apply field-level access control.",
                    evidence=f"Context: {context}",
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
