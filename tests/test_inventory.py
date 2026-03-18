"""Tests for API9:2023 - Improper Inventory Management."""
from unittest.mock import MagicMock
import pytest

from audit.checks.inventory import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    return ScanConfig(base_url="http://test.local", endpoints=endpoints or ["/api/users"])


def _mock_response(status_code=404):
    r = MagicMock()
    r.status_code = status_code
    return r


class TestInventory:
    def test_pass_when_no_old_versions_reachable(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(404)

        findings = check(config, client)

        version_pass = next(
            (f for f in findings if "version" in f.title.lower() and f.status == Status.PASS),
            None,
        )
        assert version_pass is not None

    def test_fail_when_multiple_versions_accessible(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if "/v1" in url or "/v2" in url or "/api/v1" in url or "/api/v2" in url:
                return _mock_response(200)
            return _mock_response(404)

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "version" in f.title.lower()]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.MEDIUM
        assert fails[0].check_id == "API9:2023"

    def test_fail_when_shadow_endpoint_accessible(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if url.endswith("/test") or url.endswith("/dev"):
                return _mock_response(200)
            return _mock_response(404)

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "shadow" in f.title.lower()]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.MEDIUM

    def test_pass_when_no_shadow_endpoints(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(404)

        findings = check(config, client)

        shadow_pass = next(
            (f for f in findings if "shadow" in f.title.lower() and f.status == Status.PASS),
            None,
        )
        assert shadow_pass is not None

    def test_evidence_lists_active_versions(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if "/api/v1" in url or "/api/v2" in url:
                return _mock_response(200)
            return _mock_response(404)

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fail = next((f for f in findings if f.status == Status.FAIL and f.evidence), None)
        assert fail is not None
        assert "200" in fail.evidence
