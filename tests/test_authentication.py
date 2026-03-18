"""Tests for API2:2023 - Broken Authentication check."""
from unittest.mock import MagicMock, patch
import pytest

from audit.checks.authentication import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    if endpoints is None:
        endpoints = ["/api/users"]
    return ScanConfig(base_url="http://test.local", endpoints=endpoints)


def _mock_response(status_code=200):
    r = MagicMock()
    r.status_code = status_code
    return r


class TestAuthentication:
    def test_fail_when_endpoint_accessible_without_auth(self):
        config = _config()
        client = MagicMock()
        client.request_without_auth.return_value = _mock_response(200)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "without authentication" in f.title]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.CRITICAL
        assert fails[0].check_id == "API2:2023"

    def test_pass_when_endpoint_returns_401(self):
        config = _config()
        client = MagicMock()
        client.request_without_auth.return_value = _mock_response(401)

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS]
        assert len(passes) >= 1

    def test_fail_when_invalid_token_accepted(self):
        config = _config()
        client = MagicMock()
        # First call (no auth): returns 401 — good
        # Second call (invalid token): returns 200 — bad
        client.request_without_auth.side_effect = [
            _mock_response(401),
            _mock_response(200),
        ]

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "invalid token" in f.title]
        assert len(fails) == 1
        assert fails[0].severity == Severity.CRITICAL

    def test_skip_on_connection_error(self):
        config = _config()
        client = MagicMock()
        client.request_without_auth.side_effect = ConnectionError("refused")

        findings = check(config, client)

        skips = [f for f in findings if f.status == Status.SKIP]
        assert len(skips) >= 1

    def test_no_findings_when_no_endpoints(self):
        config = _config(endpoints=[])
        client = MagicMock()

        findings = check(config, client)

        assert findings == []
