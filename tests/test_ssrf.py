"""Tests for API7:2023 - SSRF check."""
from unittest.mock import MagicMock
import pytest

from audit.checks.ssrf import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None):
    if endpoints is None:
        endpoints = ["/api/fetch"]
    return ScanConfig(base_url="http://test.local", endpoints=endpoints)


def _mock_response(status_code=200, body=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    return r


class TestSSRF:
    def test_skip_when_no_endpoints(self):
        config = _config(endpoints=[])
        client = MagicMock()

        findings = check(config, client)

        assert any(f.status == Status.SKIP for f in findings)

    def test_pass_when_no_ssrf_indicators(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(404, "not found")

        findings = check(config, client)

        assert any(f.status == Status.PASS for f in findings)
        assert not any(f.status == Status.FAIL for f in findings)

    def test_fail_when_cloud_metadata_in_response(self):
        config = _config(endpoints=["/api/fetch"])
        client = MagicMock()

        def get_side_effect(url, params=None, **kwargs):
            if params and params.get("url", "").startswith("http://169.254"):
                return _mock_response(200, body="ami-id: ami-0abcdef1234567890\ninstance-id: i-1234567890")
            return _mock_response(404, "not found")

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) >= 1
        assert fails[0].severity == Severity.CRITICAL
        assert fails[0].check_id == "API7:2023"

    def test_no_false_positive_when_signature_echoed_from_payload(self):
        # Simulates a JSONP API that echoes the callback URL back in the response body.
        # e.g. response = "http://metadata.google.internal/computeMetadata/v1/({})"
        # The word "computeMetadata" comes from the payload URL itself, not from
        # actual metadata being fetched — should NOT be flagged as SSRF.
        config = _config(endpoints=["/api/data"])
        client = MagicMock()

        def get_side_effect(url, params=None, **kwargs):
            if params:
                payload_url = next(iter(params.values()), "")
                # Echo the callback URL back like a JSONP API would
                return _mock_response(200, body=f"{payload_url}({{}})")
            return _mock_response(404, "")

        client.get.side_effect = get_side_effect

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) == 0

    def test_id_placeholder_replaced_in_endpoint(self):
        config = _config(endpoints=["/api/users/{id}/avatar"])
        client = MagicMock()
        client.get.return_value = _mock_response(404, "")

        findings = check(config, client)

        # Ensure no KeyError from {id} placeholder, check ran cleanly
        assert any(f.status in (Status.PASS, Status.WARN) for f in findings)
