"""Tests for injection checks (SQL, NoSQL, path traversal)."""
from unittest.mock import MagicMock
import pytest

from audit.checks.injection import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    return ScanConfig(base_url="http://test.local", endpoints=endpoints or ["/api/search"])


def _mock_response(status_code=200, body=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    return r


class TestInjection:
    def test_fail_on_sql_error_in_response(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(500, "You have an error in your SQL syntax near '1'='1'")

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "SQL" in f.title]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.CRITICAL

    def test_fail_on_nosql_error_in_response(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, params=None, **kwargs):
            if params and "filter" in params:
                return _mock_response(500, "MongoError: BSON operator not supported")
            return _mock_response(200, "ok")

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "NoSQL" in f.title]
        assert len(fails) >= 1

    def test_fail_on_path_traversal_with_passwd(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if "etc/passwd" in url or "%2F" in url:
                return _mock_response(200, "root:x:0:0:root:/root:/bin/bash")
            return _mock_response(200, "")

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "traversal" in f.title.lower()]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.CRITICAL

    def test_no_findings_on_clean_responses(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(200, '{"results": []}')

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) == 0

    def test_no_findings_when_no_endpoints(self):
        config = _config(endpoints=[])
        client = MagicMock()

        findings = check(config, client)

        assert findings == []
