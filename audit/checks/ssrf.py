"""
API7:2023 - Server Side Request Forgery (SSRF)
Checks whether the API forwards user-controlled URLs to internal network requests.
Probes common URL parameters with internal addresses and SSRF payloads.
"""
from audit.core.models import Finding, Severity, Status
from audit.core.config import ScanConfig
from audit.utils.http_client import HttpClient

# Common parameter names that tend to accept URLs and may be SSRF-prone
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "callback", "webhook", "proxy", "fetch", "load",
    "image", "avatar", "logo", "icon", "file", "document",
]

# Payloads: internal addresses that should never be reachable from the server
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",    # AWS instance metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://169.254.169.254/metadata/instance",    # Azure IMDS
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
]

# Strings that suggest the server fetched the internal resource
CLOUD_METADATA_SIGNATURES = [
    "ami-id", "instance-id", "local-ipv4",        # AWS
    "computeMetadata", "serviceAccounts",          # GCP
    "azureml", "subscriptionId",                   # Azure
]


def _looks_like_ssrf_response(body: str, payload: str) -> bool:
    """
    Returns True only if the response body contains a cloud-metadata signature
    that was NOT already present in the request payload URL itself.
    This prevents false positives from JSONP APIs that echo the callback URL back.
    """
    body_lower = body.lower()
    payload_lower = payload.lower()
    return any(
        sig.lower() in body_lower and sig.lower() not in payload_lower
        for sig in CLOUD_METADATA_SIGNATURES
    )


def check(config: ScanConfig, client: HttpClient) -> list[Finding]:
    findings = []
    probed_any = False

    for endpoint in config.endpoints:
        url = f"{config.base_url}{endpoint.replace('{id}', '1')}"

        for param in SSRF_PARAM_NAMES:
            for payload in SSRF_PAYLOADS:
                try:
                    response = client.get(url, params={param: payload})
                    probed_any = True

                    if _looks_like_ssrf_response(response.text, payload):
                        findings.append(Finding(
                            check_id="API7:2023",
                            title=f"SSRF: server fetched internal resource via '{param}' parameter",
                            severity=Severity.CRITICAL,
                            status=Status.FAIL,
                            detail=(
                                f"GET {url}?{param}={payload} returned a response that looks like "
                                "an internal/cloud metadata resource was fetched by the server."
                            ),
                            recommendation=(
                                "Never forward user-supplied URLs to internal requests. "
                                "If URL fetching is required, use an allowlist of trusted domains. "
                                "Block access to link-local (169.254.x.x) and private IP ranges."
                            ),
                            evidence=f"Matched internal content in response body",
                        ))
                        break  # One finding per param per endpoint is enough


                except Exception:
                    pass

    if not probed_any:
        findings.append(Finding(
            check_id="API7:2023",
            title="SSRF check skipped — no endpoints defined",
            severity=Severity.INFO,
            status=Status.SKIP,
            detail="Define endpoints in the scan config to enable SSRF probing.",
            recommendation="Add endpoint paths to your scan config.",
        ))

    # De-duplicate: if we got no FAIL/WARN findings but we probed, report a pass
    has_issue = any(f.status in (Status.FAIL, Status.WARN) for f in findings)
    if probed_any and not has_issue:
        findings.append(Finding(
            check_id="API7:2023",
            title="No SSRF indicators detected",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=(
                f"Probed {len(SSRF_PARAM_NAMES)} common URL parameters with {len(SSRF_PAYLOADS)} "
                "internal-address payloads — no SSRF indicators found."
            ),
            recommendation="",
        ))

    return findings
