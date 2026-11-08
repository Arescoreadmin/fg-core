"""L14-SCAN-COMPLETENESS-001 — DEF-001 closure tests.

Adversarial tests proving that DNS collection failures (timeout, SERVFAIL, REFUSED)
do NOT produce missing-record security findings.

Only authoritative negative responses (NO_DATA, NXDOMAIN) may produce
missing SPF / DMARC / MX / DNSSEC findings.

Tests call real runner classification logic; _dns_query is mocked.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from services.connectors.collection_status import CollectionStatus, DnsQueryStatus
from services.connectors.dns_email.runner import (
    DnsQueryOutcome,
    _check_spf,
    _check_dmarc,
    _check_mx,
    _check_dnssec,
    scan_domain,
    run,
)


def _outcome(
    status: DnsQueryStatus, records: list[str] | None = None
) -> DnsQueryOutcome:
    return DnsQueryOutcome(records=records or [], status=status)


COLLECTION_FAILURE_STATUSES = [
    DnsQueryStatus.TIMEOUT,
    DnsQueryStatus.SERVFAIL,
    DnsQueryStatus.REFUSED,
    DnsQueryStatus.RESOLVER_ERROR,
    DnsQueryStatus.MALFORMED,
]

AUTHORITATIVE_ABSENCE_STATUSES = [
    DnsQueryStatus.NO_DATA,
    DnsQueryStatus.NXDOMAIN,
]


# ---------------------------------------------------------------------------
# DEF001-SPF: SPF finding behavior
# ---------------------------------------------------------------------------


class TestDef001Spf:
    @pytest.mark.parametrize("failure_status", COLLECTION_FAILURE_STATUSES)
    def test_spf_collection_failure_does_not_produce_missing_finding(
        self, failure_status
    ):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(failure_status)
            result = _check_spf("example.com")

        assert result["finding"] is None, (
            f"{failure_status.value} must NOT produce missing_spf finding. "
            "Collection failure is not evidence of record absence."
        )
        assert result["collection_failure"] is True
        assert result["present"] is None

    @pytest.mark.parametrize("absence_status", AUTHORITATIVE_ABSENCE_STATUSES)
    def test_spf_authoritative_absence_produces_missing_finding(self, absence_status):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(absence_status)
            result = _check_spf("example.com")

        assert result["finding"] == "missing_spf", (
            f"{absence_status.value} is authoritative absence; missing_spf finding must be emitted."
        )
        assert result["collection_failure"] is False
        assert result["present"] is False
        assert result["collection_status"] == CollectionStatus.COMPLETE.value

    def test_spf_timeout_collection_status_is_timeout(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.TIMEOUT)
            result = _check_spf("example.com")

        assert result["collection_status"] == CollectionStatus.TIMEOUT.value

    def test_spf_servfail_collection_status_is_failed(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.SERVFAIL)
            result = _check_spf("example.com")

        assert result["collection_status"] == CollectionStatus.FAILED.value


# ---------------------------------------------------------------------------
# DEF001-DMARC: DMARC finding behavior
# ---------------------------------------------------------------------------


class TestDef001Dmarc:
    @pytest.mark.parametrize("failure_status", COLLECTION_FAILURE_STATUSES)
    def test_dmarc_collection_failure_does_not_produce_missing_finding(
        self, failure_status
    ):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(failure_status)
            result = _check_dmarc("example.com")

        assert result["finding"] is None, (
            f"{failure_status.value} must NOT produce missing_dmarc finding."
        )
        assert result["collection_failure"] is True

    @pytest.mark.parametrize("absence_status", AUTHORITATIVE_ABSENCE_STATUSES)
    def test_dmarc_authoritative_absence_produces_missing_finding(self, absence_status):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(absence_status)
            result = _check_dmarc("example.com")

        assert result["finding"] == "missing_dmarc"
        assert result["collection_failure"] is False


# ---------------------------------------------------------------------------
# DEF001-MX: MX finding behavior
# ---------------------------------------------------------------------------


class TestDef001Mx:
    @pytest.mark.parametrize("failure_status", COLLECTION_FAILURE_STATUSES)
    def test_mx_collection_failure_does_not_produce_no_mx_finding(self, failure_status):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(failure_status)
            result = _check_mx("example.com")

        assert result["finding"] is None, (
            f"{failure_status.value} must NOT produce no_mx finding."
        )
        assert result["collection_failure"] is True

    @pytest.mark.parametrize("absence_status", AUTHORITATIVE_ABSENCE_STATUSES)
    def test_mx_authoritative_absence_produces_no_mx_finding(self, absence_status):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(absence_status)
            result = _check_mx("example.com")

        assert result["finding"] == "no_mx"
        assert result["collection_failure"] is False


# ---------------------------------------------------------------------------
# DEF001-DNSSEC: DNSSEC finding behavior
# ---------------------------------------------------------------------------


class TestDef001Dnssec:
    @pytest.mark.parametrize("failure_status", COLLECTION_FAILURE_STATUSES)
    def test_dnssec_collection_failure_does_not_produce_finding(self, failure_status):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(failure_status)
            result = _check_dnssec("example.com")

        assert result["finding"] is None, (
            f"{failure_status.value} must NOT produce dnssec_not_enabled finding."
        )
        assert result["collection_failure"] is True

    def test_dnssec_authoritative_no_dnskey_produces_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.NO_DATA)
            result = _check_dnssec("example.com")

        assert result["finding"] == "dnssec_not_enabled"
        assert result["collection_failure"] is False


# ---------------------------------------------------------------------------
# DEF001-DOMAIN: Domain-level scan_domain aggregation
# ---------------------------------------------------------------------------


class TestDef001ScanDomain:
    def test_all_timeout_produces_no_findings(self):
        """When all DNS queries time out, no security findings must be emitted."""
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.TIMEOUT)
            result = scan_domain("timeout.example.com")

        assert result["findings"] == [], (
            "All-timeout scan must produce no findings. "
            "Timeout is indeterminate, not verified record absence."
        )
        assert result["any_collection_failure"] is True
        # Domain collection status should reflect failure
        assert result["collection_status"] != CollectionStatus.COMPLETE.value

    def test_partial_timeout_suppresses_timeout_domain_findings(self):
        """When DMARC times out but SPF succeeds (absent), SPF finding is emitted
        but no DMARC finding is emitted (since DMARC collection failed)."""

        def selective_mock(name: str, rdtype: str) -> DnsQueryOutcome:
            if "_dmarc" in name:
                return _outcome(DnsQueryStatus.TIMEOUT)
            if rdtype == "TXT" and "_dmarc" not in name and "domainkey" not in name:
                return _outcome(DnsQueryStatus.NO_DATA)  # SPF absent
            return _outcome(DnsQueryStatus.NO_DATA)

        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=selective_mock,
        ):
            result = scan_domain("example.com")

        finding_types = [f["type"] for f in result["findings"]]
        # SPF is verified absent (NO_DATA) → missing_spf is correct
        assert "missing_spf" in finding_types
        # DMARC timed out → no missing_dmarc finding
        assert "missing_dmarc" not in finding_types, (
            "DMARC timeout must NOT produce missing_dmarc finding."
        )

    def test_all_collection_failure_produces_failed_status(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.SERVFAIL)
            result = scan_domain("example.com")

        assert result["collection_status"] == CollectionStatus.FAILED.value

    def test_partial_failure_produces_partial_status(self):
        """Some checks fail, some succeed → PARTIAL."""
        call_count = [0]

        def alternate_mock(name: str, rdtype: str) -> DnsQueryOutcome:
            call_count[0] += 1
            if "_dmarc" in name:
                return _outcome(DnsQueryStatus.TIMEOUT)
            return _outcome(
                DnsQueryStatus.SUCCESS,
                records=['"v=spf1 -all"']
                if rdtype == "TXT" and "_" not in name
                else [],
            )

        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=alternate_mock,
        ):
            result = scan_domain("example.com")

        assert result["collection_status"] == CollectionStatus.PARTIAL.value
        assert result["any_collection_failure"] is True


# ---------------------------------------------------------------------------
# DEF001-RUN: run() collection_status propagation
# ---------------------------------------------------------------------------


class TestDef001Run:
    def test_all_complete_produces_complete_status(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.NO_DATA)
            result = run(["example.com"])

        assert result["collection_status"] == CollectionStatus.COMPLETE.value
        assert result["summary"]["domains_with_collection_failures"] == 0

    def test_all_timeout_produces_failed_status(self):
        with patch("services.connectors.dns_email.runner._dns_query") as m:
            m.return_value = _outcome(DnsQueryStatus.TIMEOUT)
            result = run(["example.com"])

        assert result["collection_status"] != CollectionStatus.COMPLETE.value

    def test_mixed_produces_partial_status(self):
        def mixed_mock(name: str, rdtype: str) -> DnsQueryOutcome:
            if "timeout" in name:
                return _outcome(DnsQueryStatus.TIMEOUT)
            return _outcome(DnsQueryStatus.NO_DATA)

        with patch(
            "services.connectors.dns_email.runner._dns_query", side_effect=mixed_mock
        ):
            result = run(["good.example.com", "timeout.example.com"])

        assert result["collection_status"] == CollectionStatus.PARTIAL.value
        assert result["summary"]["domains_with_collection_failures"] == 1
