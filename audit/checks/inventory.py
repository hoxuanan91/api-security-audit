"""
API9:2023 - Improper Inventory Management
Checks whether old or undocumented API versions are still accessible,
and whether debug/test/internal endpoints are exposed in production.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient

# Old and shadow API version prefixes to probe
VERSION_PREFIXES = [
    "/v1", "/v2", "/v3", "/v4",
    "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1.0", "/api/v1.1", "/api/v2.0",
    "/api-v1", "/api-v2",
]

# Paths that should not exist in production
SHADOW_PATHS = [
    "/test",
    "/dev",
    "/staging",
    "/beta",
    "/alpha",
    "/old",
    "/legacy",
    "/deprecated",
    "/backup",
    "/api/test",
    "/api/dev",
    "/api/beta",
    "/api/old",
    "/api/legacy",
    "/api/internal",
    "/api/private",
    "/api/mock",
    "/api/sandbox",
    "/api/demo",
]


def _is_alive(status_code: int) -> bool:
    """Returns True if the response suggests the endpoint actually exists."""
    return status_code not in (404, 410)


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []

    # ── Test 1: old API versions ────────────────────────────────────────────
    active_versions = []
    current_version = _detect_current_version(config.base_url, config.endpoints)

    for prefix in VERSION_PREFIXES:
        url = f"{config.base_url}{prefix}"
        try:
            response = client.get(url)
            if _is_alive(response.status_code):
                active_versions.append((prefix, response.status_code))
        except Exception:
            pass

    if len(active_versions) > 1:
        # More than one version alive — old versions are likely still running
        older = [v for v, _ in active_versions if v != current_version]
        if older:
            findings.append(Finding(
                check_id="API9:2023",
                title="Multiple API versions accessible — old versions may be unpatched",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                detail=(
                    f"Found {len(active_versions)} active API version prefixes: "
                    f"{', '.join(v for v, _ in active_versions)}. "
                    "Old versions often lack security patches applied to the latest version."
                ),
                recommendation=(
                    "Decommission old API versions or redirect them to the latest. "
                    "Maintain an inventory of all active API versions and their deprecation dates."
                ),
                evidence=", ".join(f"{v} ({s})" for v, s in active_versions),
            ))
    elif len(active_versions) == 1:
        findings.append(Finding(
            check_id="API9:2023",
            title=f"Single API version detected: {active_versions[0][0]}",
            severity=Severity.INFO,
            status=Status.PASS,
            detail="Only one versioned API prefix is accessible.",
            recommendation="",
        ))
    else:
        findings.append(Finding(
            check_id="API9:2023",
            title="No versioned API prefixes detected",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=f"Probed {len(VERSION_PREFIXES)} version prefixes — none accessible.",
            recommendation="",
        ))

    # ── Test 2: shadow / undocumented endpoints ──────────────────────────────
    exposed_shadows = []
    for path in SHADOW_PATHS:
        url = f"{config.base_url}{path}"
        try:
            response = client.get(url)
            if _is_alive(response.status_code):
                exposed_shadows.append((path, response.status_code))
        except Exception:
            pass

    if exposed_shadows:
        for path, code in exposed_shadows:
            findings.append(Finding(
                check_id="API9:2023",
                title=f"Shadow/undocumented endpoint accessible: {path}",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                detail=(
                    f"GET {config.base_url}{path} returned HTTP {code}. "
                    "Test, dev, legacy, or internal endpoints should never be "
                    "reachable in a production environment."
                ),
                recommendation=(
                    "Remove or disable non-production endpoints before deploying. "
                    "Use environment-based routing to block /test, /dev, /legacy paths in prod."
                ),
                evidence=f"Status: {code}",
            ))
    else:
        findings.append(Finding(
            check_id="API9:2023",
            title="No shadow endpoints detected",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=f"Probed {len(SHADOW_PATHS)} shadow/legacy paths — none accessible.",
            recommendation="",
        ))

    return findings


def _detect_current_version(base_url: str, endpoints: list[str]) -> str | None:
    """Best-effort guess of the current API version from configured endpoints."""
    for endpoint in endpoints:
        for part in endpoint.split("/"):
            if part.startswith("v") and part[1:].isdigit():
                return f"/{part}"
    return None
