"""Tests for API8:2023 - Security Headers check."""
from unittest.mock import MagicMock
import pytest

from audit.checks.headers import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity
from audit.utils.patterns import SECURITY_HEADERS


def _config():
    return ScanConfig(base_url="http://test.local", endpoints=["/api"])


def _mock_response(headers=None, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    r.headers = headers or {}
    return r


class TestHeaders:
    def test_fail_for_missing_hsts(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(headers={})

        findings = check(config, client)

        hsts_fail = next(
            (f for f in findings if "Strict-Transport-Security" in f.title and f.status == Status.FAIL),
            None,
        )
        assert hsts_fail is not None
        assert hsts_fail.severity == Severity.HIGH

    def test_pass_for_present_headers(self):
        config = _config()
        client = MagicMock()
        all_headers = {h: "value" for h in SECURITY_HEADERS}
        client.get.return_value = _mock_response(headers=all_headers)

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS]
        assert len(passes) == len(SECURITY_HEADERS)

    def test_fail_wildcard_cors(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(headers={"Access-Control-Allow-Origin": "*"})

        findings = check(config, client)

        cors_fail = next(
            (f for f in findings if "CORS" in f.title and f.status == Status.FAIL),
            None,
        )
        assert cors_fail is not None
        assert cors_fail.severity == Severity.HIGH

    def test_no_cors_finding_when_header_absent(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(headers={})

        findings = check(config, client)

        cors_fail = next((f for f in findings if "CORS" in f.title), None)
        assert cors_fail is None

    def test_skip_on_connection_error(self):
        config = _config()
        client = MagicMock()
        client.get.side_effect = ConnectionError("refused")

        findings = check(config, client)

        assert len(findings) == 1
        assert findings[0].status == Status.SKIP

    def test_csp_missing_severity_is_high(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(headers={})

        findings = check(config, client)

        csp_fail = next(
            (f for f in findings if "Content-Security-Policy" in f.title and f.status == Status.FAIL),
            None,
        )
        assert csp_fail is not None
        assert csp_fail.severity == Severity.HIGH
