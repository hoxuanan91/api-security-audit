"""
API5:2023 - Broken Function Level Authorization (BFLA)
Checks whether privileged/admin endpoints are accessible to regular users.
Probes common admin paths and HTTP methods (PUT/DELETE) that should be restricted.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient

# Common admin/privileged paths to probe
ADMIN_PATHS = [
    "/admin",
    "/admin/users",
    "/admin/dashboard",
    "/api/admin",
    "/api/v1/admin",
    "/management",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/_debug",
    "/debug",
    "/internal",
    "/console",
    "/swagger-ui.html",
    "/swagger-ui",
    "/api-docs",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
]


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    # Test 1: probe known admin/privileged paths
    accessible_admin = []
    for path in ADMIN_PATHS:
        url = f"{config.base_url}{path}"
        try:
            response = client.get(url)
            if response.status_code not in (401, 403, 404):
                accessible_admin.append((path, response.status_code))
        except Exception:
            pass

    if accessible_admin:
        for path, code in accessible_admin:
            # Swagger/API-doc exposure is lower severity than actual admin panels
            is_docs = any(kw in path for kw in ("swagger", "api-docs", "openapi"))
            severity = Severity.MEDIUM if is_docs else Severity.HIGH
            findings.append(Finding(
                check_id="API5:2023",
                title=f"Privileged path accessible: {path}",
                severity=severity,
                status=Status.FAIL,
                detail=f"GET {config.base_url}{path} returned HTTP {code}. This endpoint may expose admin or debug functionality.",
                recommendation=(
                    "Restrict admin and management endpoints to authorized roles only. "
                    "Return 403 (not 404) for authenticated but unauthorized access."
                ),
                evidence=f"Status: {code}",
            ))
    else:
        findings.append(Finding(
            check_id="API5:2023",
            title="No exposed admin paths detected",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=f"Probed {len(ADMIN_PATHS)} common admin paths — all returned 401/403/404.",
            recommendation="",
        ))

    # Test 2: attempt privileged HTTP methods (PUT/DELETE) on user endpoints
    for endpoint in config.endpoints:
        if "{id}" in endpoint:
            url = f"{config.base_url}{endpoint.replace('{id}', '1')}"
        else:
            url = f"{config.base_url}{endpoint}"

        for method in ("DELETE", "PUT"):
            try:
                response = client.request_without_auth(method, url, json={})
                if response.status_code not in (401, 403, 404, 405):
                    findings.append(Finding(
                        check_id="API5:2023",
                        title=f"Privileged method allowed without auth: {method} {endpoint}",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        detail=(
                            f"{method} {url} returned {response.status_code} without authentication. "
                            "Write methods should require valid credentials."
                        ),
                        recommendation=(
                            "Enforce authentication and role checks on all write/delete operations. "
                            "Return 401 for missing credentials, 403 for insufficient permissions."
                        ),
                        evidence=f"Status: {response.status_code}",
                    ))
            except Exception:
                pass

    return findings
