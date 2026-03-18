"""Tests for API4:2023 - Rate Limiting check."""
from unittest.mock import MagicMock
import pytest

from audit.checks.rate_limiting import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(threshold=5):
    return ScanConfig(
        base_url="http://test.local",
        endpoints=["/api/users"],
        rate_limit_threshold=threshold,
    )


def _mock_response(status_code=200, headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.headers = headers or {}
    return r


class TestRateLimiting:
    def test_pass_when_429_received(self):
        config = _config(threshold=5)
        client = MagicMock()
        # Returns 200 three times then 429
        client.get.side_effect = [
            _mock_response(200),
            _mock_response(200),
            _mock_response(429),
        ]

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS and "429" in f.title]
        assert len(passes) == 1

    def test_fail_when_no_429_after_threshold(self):
        config = _config(threshold=5)
        client = MagicMock()
        client.get.return_value = _mock_response(200)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.HIGH

    def test_pass_with_rate_limit_headers(self):
        config = _config(threshold=3)
        client = MagicMock()
        client.get.return_value = _mock_response(
            200, headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"}
        )

        findings = check(config, client)

        header_pass = next(
            (f for f in findings if "headers" in f.title.lower() and f.status == Status.PASS),
            None,
        )
        assert header_pass is not None

    def test_warn_when_rate_limit_headers_missing(self):
        config = _config(threshold=3)
        client = MagicMock()
        client.get.return_value = _mock_response(200, headers={})

        findings = check(config, client)

        header_warn = next(
            (f for f in findings if "headers" in f.title.lower() and f.status == Status.WARN),
            None,
        )
        assert header_warn is not None

    def test_skip_on_connection_error(self):
        config = _config()
        client = MagicMock()
        client.get.side_effect = ConnectionError("refused")

        findings = check(config, client)

        assert len(findings) == 1
        assert findings[0].status == Status.SKIP

    def test_no_findings_when_no_endpoints(self):
        config = ScanConfig(base_url="http://test.local", endpoints=[])
        client = MagicMock()

        findings = check(config, client)

        assert findings == []
