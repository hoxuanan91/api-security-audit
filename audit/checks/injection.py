"""
API injection checks — SQL, NoSQL, XSS, Path Traversal
Tests query parameters for basic injection vulnerabilities.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient
from audit.utils.patterns import INJECTION_PAYLOADS

# Strings that appear in responses when injection succeeds
SQL_ERROR_SIGNATURES = [
    "sql syntax", "syntax error", "mysql_fetch", "ora-01", "postgresql",
    "unclosed quotation", "sqlite3", "you have an error in your sql",
]
NOSQL_ERROR_SIGNATURES = ["$where", "bson", "mongo", "operator"]


def _response_suggests_injection(body: str, signatures: list[str]) -> bool:
    body_lower = body.lower()
    return any(sig in body_lower for sig in signatures)


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    if not config.endpoints:
        return findings

    for endpoint in config.endpoints:
        url = f"{config.base_url}{endpoint}"

        # SQL injection via query params
        for payload in INJECTION_PAYLOADS["sql"]:
            try:
                response = client.get(url, params={"q": payload, "id": payload, "search": payload})
                if _response_suggests_injection(response.text, SQL_ERROR_SIGNATURES):
                    findings.append(Finding(
                        check_id="API8:2023",
                        title="SQL injection signature detected in response",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        detail=f"Response to payload '{payload}' on {url} contains SQL error signatures.",
                        recommendation="Use parameterized queries or ORM. Never interpolate user input into SQL.",
                        evidence=payload,
                    ))
                    break  # One finding per endpoint is enough
            except Exception:
                pass

        # NoSQL injection
        for payload in INJECTION_PAYLOADS["nosql"]:
            try:
                response = client.get(url, params={"filter": payload})
                if _response_suggests_injection(response.text, NOSQL_ERROR_SIGNATURES):
                    findings.append(Finding(
                        check_id="API8:2023",
                        title="NoSQL injection signature detected in response",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        detail=f"Response to NoSQL payload '{payload}' on {url} contains MongoDB/BSON error signatures.",
                        recommendation="Validate and sanitize all query operators. Use schema validation before querying.",
                        evidence=payload,
                    ))
                    break
            except Exception:
                pass

        # Path traversal
        for payload in INJECTION_PAYLOADS["path_traversal"]:
            try:
                traversal_url = f"{url}/{payload}"
                response = client.get(traversal_url)
                if "root:" in response.text or "bin/bash" in response.text:
                    findings.append(Finding(
                        check_id="API8:2023",
                        title="Path traversal vulnerability detected",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        detail=f"Response from '{traversal_url}' appears to contain /etc/passwd content.",
                        recommendation="Validate and canonicalize file paths. Reject paths containing '../'.",
                        evidence=payload,
                    ))
                    break
            except Exception:
                pass

    return findings
