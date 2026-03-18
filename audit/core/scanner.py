from audit.core.config import ScanConfig
from audit.core.models import AuditResult
from audit.utils.http_client import HttpClient
from audit.checks import authentication, headers, data_exposure, rate_limiting, bola, injection, bfla, ssrf, business_flows, inventory


CHECKS = [
    ("BOLA (API1:2023)", bola.check),
    ("Authentication (API2:2023)", authentication.check),
    ("Data Exposure (API3:2023)", data_exposure.check),
    ("Rate Limiting (API4:2023)", rate_limiting.check),
    ("Function-Level Authorization (API5:2023)", bfla.check),
    ("Business Flows (API6:2023)", business_flows.check),
    ("SSRF (API7:2023)", ssrf.check),
    ("Security Headers (API8:2023)", headers.check),
    ("Injection (API8:2023)", injection.check),
    ("Inventory Management (API9:2023)", inventory.check),
]


def run(config: ScanConfig, progress_callback=None) -> AuditResult:
    client = HttpClient(
        token=config.token,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
    )
    result = AuditResult(target=config.base_url)

    for name, check_fn in CHECKS:
        if progress_callback:
            progress_callback(name)
        findings = check_fn(config, client)
        for finding in findings:
            result.add(finding)

    return result
