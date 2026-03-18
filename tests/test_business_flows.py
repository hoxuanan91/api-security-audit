"""Tests for API6:2023 - Unrestricted Access to Sensitive Business Flows."""
from unittest.mock import MagicMock
import pytest

from audit.checks.business_flows import check, ABUSE_THRESHOLD
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config():
    return ScanConfig(base_url="http://test.local", endpoints=["/api/users"])


def _mock_response(status_code=200, headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.headers = headers or {}
    return r


class TestBusinessFlows:
    def test_skip_when_no_sensitive_endpoints_reachable(self):
        config = _config()
        client = MagicMock()
        client.post.return_value = _mock_response(404)

        findings = check(config, client)

        assert any(f.status == Status.SKIP for f in findings)

    def test_fail_when_login_not_rate_limited(self):
        config = _config()
        client = MagicMock()

        def post_side_effect(url, **kwargs):
            if "login" in url:
                return _mock_response(200)
            return _mock_response(404)

        client.post.side_effect = post_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "login" in f.title]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.HIGH
        assert fails[0].check_id == "API6:2023"

    def test_pass_when_login_returns_429(self):
        config = _config()
        client = MagicMock()

        call_count = {"n": 0}

        def post_side_effect(url, **kwargs):
            if "login" in url:
                call_count["n"] += 1
                if call_count["n"] >= 3:
                    return _mock_response(429)
                return _mock_response(200)
            return _mock_response(404)

        client.post.side_effect = post_side_effect

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS and "login" in f.title]
        assert len(passes) >= 1

    def test_warn_when_rate_limit_headers_missing(self):
        config = _config()
        client = MagicMock()

        def post_side_effect(url, **kwargs):
            if "login" in url:
                return _mock_response(200, headers={})
            return _mock_response(404)

        client.post.side_effect = post_side_effect

        findings = check(config, client)

        warns = [f for f in findings if f.status == Status.WARN]
        assert len(warns) >= 1

    def test_pass_when_blocked_with_423(self):
        config = _config()
        client = MagicMock()

        def post_side_effect(url, **kwargs):
            if "register" in url:
                return _mock_response(423)
            return _mock_response(404)

        client.post.side_effect = post_side_effect

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS and "register" in f.title]
        assert len(passes) >= 1
