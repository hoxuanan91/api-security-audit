"""Tests for API3:2023 - Data Exposure check."""
from unittest.mock import MagicMock
import pytest

from audit.checks.data_exposure import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    return ScanConfig(base_url="http://test.local", endpoints=endpoints or ["/api/users"])


def _mock_response(status_code=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    r.headers = headers or {"Content-Type": "application/json"}

    def json_side_effect():
        import json
        return json.loads(body) if body else {}

    r.json.side_effect = json_side_effect
    return r


class TestDataExposure:
    def test_fail_on_credit_card_in_response(self):
        config = _config()
        client = MagicMock()
        body = '{"number": "4111111111111111", "name": "John"}'
        client.get.return_value = _mock_response(200, body)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "Credit card" in f.title]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.CRITICAL

    def test_fail_on_jwt_in_response(self):
        config = _config()
        client = MagicMock()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        body = f'{{"token": "{jwt}"}}'
        client.get.return_value = _mock_response(200, body)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "JWT" in f.title]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.HIGH

    def test_fail_on_stack_trace_in_error_response(self):
        config = _config()
        client = MagicMock()

        def get_side_effect(url, **kwargs):
            if url.endswith("/nonexistent_path_xyz"):
                return _mock_response(500, "Traceback (most recent call last):\n  File app.py line 10")
            return _mock_response(200, "{}")

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL and "error" in f.title.lower()]
        assert len(fails) >= 1

    def test_warn_on_excessive_fields(self):
        config = _config()
        client = MagicMock()
        # Object with 25 fields
        big_obj = {f"field{i}": i for i in range(25)}
        import json
        body = json.dumps([big_obj])
        client.get.return_value = _mock_response(200, body)

        findings = check(config, client)

        warns = [f for f in findings if f.status == Status.WARN and "excessive" in f.title.lower()]
        assert len(warns) >= 1

    def test_skip_on_connection_error(self):
        config = _config()
        client = MagicMock()
        client.get.side_effect = ConnectionError("refused")

        findings = check(config, client)

        assert any(f.status == Status.SKIP for f in findings)

    def test_clean_response_produces_no_fails(self):
        config = _config()
        client = MagicMock()
        body = '{"id": 1, "name": "Alice"}'
        client.get.return_value = _mock_response(200, body)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) == 0
