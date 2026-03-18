"""Tests for API1:2023 - BOLA check."""
from unittest.mock import MagicMock
import pytest

from audit.checks.bola import check
from audit.core.config import ScanConfig
from audit.core.models import Status, Severity


def _config(endpoints=None, bola_range=(1, 3)):
    return ScanConfig(
        base_url="http://test.local",
        endpoints=endpoints or ["/api/users/{id}"],
        bola_id_range=bola_range,
    )


def _mock_response(status_code=200):
    r = MagicMock()
    r.status_code = status_code
    return r


class TestBola:
    def test_skip_when_no_id_endpoints(self):
        config = _config(endpoints=["/api/users"])
        client = MagicMock()

        findings = check(config, client)

        assert len(findings) == 1
        assert findings[0].status == Status.SKIP

    def test_fail_when_multiple_ids_accessible(self):
        config = _config()
        client = MagicMock()
        # IDs 1, 2, 3 all return 200
        client.get.return_value = _mock_response(200)

        findings = check(config, client)

        fails = [f for f in findings if f.status == Status.FAIL]
        assert len(fails) == 1
        assert fails[0].severity == Severity.CRITICAL
        assert fails[0].check_id == "API1:2023"

    def test_warn_when_single_id_accessible(self):
        config = _config(bola_range=(1, 5))
        client = MagicMock()
        # Only ID 1 returns 200, rest return 404
        def get_side_effect(url, **kwargs):
            return _mock_response(200) if url.endswith("/1") else _mock_response(404)
        client.get.side_effect = get_side_effect

        findings = check(config, client)

        warns = [f for f in findings if f.status == Status.WARN]
        assert len(warns) == 1

    def test_pass_when_no_ids_accessible(self):
        config = _config()
        client = MagicMock()
        client.get.return_value = _mock_response(404)

        findings = check(config, client)

        passes = [f for f in findings if f.status == Status.PASS]
        assert len(passes) == 1

    def test_evidence_shows_accessible_ids(self):
        config = _config(bola_range=(1, 2))
        client = MagicMock()
        client.get.return_value = _mock_response(200)

        findings = check(config, client)

        fail = next(f for f in findings if f.status == Status.FAIL)
        assert "ID=1" in fail.evidence
        assert "ID=2" in fail.evidence
