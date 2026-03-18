"""Tests for API5:2023 - Broken Function Level Authorization check."""
from unittest.mock import MagicMock, call
import pytest

from audit.checks.bfla import check, ADMIN_PATHS
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    return ScanConfig(base_url="http://test.local", endpoints=endpoints or ["/api/users"])


def _mock_response(status_code=404):
    r = MagicMock()
    r.status_code = status_code
    return r


class TestBFLA:
    def test_fail_when_admin_path_accessible(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if "/admin" in url and not any(sub in url for sub in ("/api/admin", "/actuator", "/swagger", "/api-docs", "/openapi", "/console", "/debug", "/internal", "/management", "/_debug")):
                return _mock_response(200)
            return _mock_response(404)

        client.get.side_effect = get_side_effect
        client.request_without_auth.return_value = _mock_response(405)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "/admin" in f.title]
        assert len(fails) >= 1
        assert all(f.check_id == "API5:2023" for f in fails)

    def test_pass_when_all_admin_paths_return_403_or_404(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(404)
        client.request_without_auth.return_value = _mock_response(405)

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS]
        assert len(passes) >= 1

    def test_fail_when_delete_allowed_without_auth(self):
        config = _config(endpoints=["/api/users/{id}"])
        client = MagicMock()
        client.get.return_value = _mock_response(404)

        def request_side_effect(method, url, **kwargs):
            if method == "DELETE":
                return _mock_response(200)
            return _mock_response(405)

        client.request_without_auth.side_effect = request_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "DELETE" in f.title]
        assert len(fails) == 1
        assert fails[0].severity == Severity.HIGH

    def test_fail_when_put_allowed_without_auth(self):
        config = _config(endpoints=["/api/items"])
        client = MagicMock()
        client.get.return_value = _mock_response(404)

        def request_side_effect(method, url, **kwargs):
            if method == "PUT":
                return _mock_response(200)
            return _mock_response(405)

        client.request_without_auth.side_effect = request_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "PUT" in f.title]
        assert len(fails) == 1

    def test_swagger_exposure_is_medium_severity(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if "swagger" in url or "api-docs" in url or "openapi" in url:
                return _mock_response(200)
            return _mock_response(404)

        client.get.side_effect = get_side_effect
        client.request_without_auth.return_value = _mock_response(405)

        findings = check(config, client)

        doc_fails = [f for f in findings if f.status == Status.FAIL and f.severity == Severity.MEDIUM]
        assert len(doc_fails) >= 1
