"""
API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
Checks whether object IDs in URL paths are properly access-controlled.
Probes sequential IDs with the authenticated user to detect unauthorized access.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    """
    Probes endpoints that contain '{id}' placeholders with sequential numeric IDs.
    If the server returns 200 for IDs the authenticated user should not own,
    it indicates a potential BOLA vulnerability.
    """
    findings = []
    id_endpoints = [e for e in config.endpoints if "{id}" in e]

    if not id_endpoints:
        findings.append(Finding(
            check_id="API1:2023",
            title="BOLA check skipped — no {id} endpoints defined",
            severity=Severity.INFO,
            status=Status.SKIP,
            detail="Define endpoints with {id} placeholder in config to enable BOLA probing.",
            recommendation="Add endpoints like /api/users/{id} to your scan config.",
        ))
        return findings

    start, end = config.bola_id_range
    accessible_ids = []

    for endpoint in id_endpoints:
        for resource_id in range(start, end + 1):
            url = f"{config.base_url}{endpoint.replace('{id}', str(resource_id))}"
            try:
                response = client.get(url)
                if response.status_code == 200:
                    accessible_ids.append((resource_id, url))
            except Exception:
                pass

        if len(accessible_ids) > 1:
            findings.append(Finding(
                check_id="API1:2023",
                title="Potential BOLA — multiple sequential IDs accessible",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                detail=(
                    f"The authenticated user can access {len(accessible_ids)} resources via sequential IDs "
                    f"on {endpoint}. This may indicate missing ownership checks."
                ),
                recommendation=(
                    "Always verify that the authenticated user owns the requested resource. "
                    "Never rely solely on the ID being 'hard to guess'."
                ),
                evidence=", ".join(f"ID={i}" for i, _ in accessible_ids[:5]),
            ))
        elif len(accessible_ids) == 1:
            findings.append(Finding(
                check_id="API1:2023",
                title="Single ID accessible — BOLA inconclusive",
                severity=Severity.INFO,
                status=Status.WARN,
                detail=f"Only one ID ({accessible_ids[0][0]}) returned 200. Cannot confirm BOLA without a second authenticated user.",
                recommendation="Test with two different user tokens to confirm authorization is enforced per object.",
            ))
        else:
            findings.append(Finding(
                check_id="API1:2023",
                title="No sequential ID access detected",
                severity=Severity.INFO,
                status=Status.PASS,
                detail=f"No IDs in range {start}–{end} returned 200 on {endpoint}.",
                recommendation="",
            ))

    return findings
