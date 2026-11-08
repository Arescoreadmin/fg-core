"""L14-SCAN-ACCURACY-001 — DNS/email scanner known-answer accuracy tests.

Updated by L14-SCAN-COMPLETENESS-001: _dns_query now returns DnsQueryOutcome
(not list[str]). Mock helper updated accordingly. SA-DNS-014 updated to test
the FIXED behavior (DEF-001 closed: timeout → no finding emitted).

Calls real scanner classification/finding-emitter logic.
Mocks only _dns_query (external I/O boundary).
Does NOT mock _check_spf, _check_dmarc, _check_dkim, _check_mx, _check_dnssec,
or scan_domain finding-emitter logic.

Critical truth conditions tested:
- Unknown DKIM selector does NOT produce DKIM_GLOBALLY_MISSING
- DNSKEY presence does NOT become DNSSEC_CHAIN_VALIDATED
- DNS timeout does NOT produce SPF_MISSING or DMARC_MISSING findings (DEF-001 closed)
"""

from __future__ import annotations

from unittest.mock import patch

from services.connectors.collection_status import CollectionStatus, DnsQueryStatus
from services.connectors.dns_email.runner import (
    DnsQueryOutcome,
    _check_spf,
    _check_dmarc,
    _check_dkim,
    _check_mx,
    _check_dnssec,
    scan_domain,
    run,
)

# ---------------------------------------------------------------------------
# Helpers — mock _dns_query at the module level
# ---------------------------------------------------------------------------


def _mock_dns_query_factory(
    response_map: dict[tuple[str, str], list[str]],
    *,
    default_status: DnsQueryStatus = DnsQueryStatus.NO_DATA,
):
    """Return a _dns_query mock that returns pre-defined DnsQueryOutcome objects.

    Records present in response_map → SUCCESS status with those records.
    Records absent from response_map → NO_DATA status (authoritative absence).
    """

    def _mock(name: str, rdtype: str) -> DnsQueryOutcome:
        if (name, rdtype) in response_map:
            records = response_map[(name, rdtype)]
            if records:
                return DnsQueryOutcome(records=records, status=DnsQueryStatus.SUCCESS)
            else:
                return DnsQueryOutcome(records=[], status=DnsQueryStatus.NO_DATA)
        return DnsQueryOutcome(records=[], status=default_status)

    return _mock


def _timeout_query(name: str, rdtype: str) -> DnsQueryOutcome:
    """Mock that always returns TIMEOUT."""
    return DnsQueryOutcome(
        records=[], status=DnsQueryStatus.TIMEOUT, raw_error="timeout"
    )


def _servfail_query(name: str, rdtype: str) -> DnsQueryOutcome:
    """Mock that always returns SERVFAIL."""
    return DnsQueryOutcome(
        records=[], status=DnsQueryStatus.SERVFAIL, raw_error="servfail"
    )


# ---------------------------------------------------------------------------
# SA-DNS-001: valid_spf → no SPF finding
# ---------------------------------------------------------------------------


class TestValidSpf:
    def test_valid_spf_strict_no_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com -all"'],
                }
            )
            result = _check_spf("example.com")

        assert result["present"] is True
        assert result["finding"] is None, (
            "v=spf1 ... -all is a valid strict SPF record; no finding should be emitted."
        )
        assert result["collection_status"] == CollectionStatus.COMPLETE.value
        assert result["collection_failure"] is False


# ---------------------------------------------------------------------------
# SA-DNS-002: permissive_spf → SPF_PERMISSIVE finding
# ---------------------------------------------------------------------------


class TestPermissiveSpf:
    def test_plus_all_produces_spf_permissive(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com +all"'],
                }
            )
            result = _check_spf("example.com")

        assert result["finding"] == "spf_permissive"

    def test_question_all_produces_spf_permissive(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 ip4:1.2.3.4 ?all"'],
                }
            )
            result = _check_spf("example.com")

        assert result["finding"] == "spf_permissive"


# ---------------------------------------------------------------------------
# SA-DNS-003: missing_spf → SPF_MISSING finding (authoritative absence)
# ---------------------------------------------------------------------------


class TestMissingSpf:
    def test_no_spf_record_produces_missing_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=TXT some-other-record"'],
                }
            )
            result = _check_spf("example.com")

        assert result["present"] is False
        assert result["finding"] == "missing_spf"
        assert result["collection_status"] == CollectionStatus.COMPLETE.value
        assert result["collection_failure"] is False


# ---------------------------------------------------------------------------
# SA-DNS-004: strong_dmarc → no finding (DMARC_ENFORCED)
# ---------------------------------------------------------------------------


class TestStrongDmarc:
    def test_dmarc_reject_produces_no_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("_dmarc.example.com", "TXT"): [
                        '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
                    ],
                }
            )
            result = _check_dmarc("example.com")

        assert result["present"] is True
        assert result["policy"] == "reject"
        assert result["finding"] is None

    def test_dmarc_quarantine_produces_no_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("_dmarc.example.com", "TXT"): [
                        '"v=DMARC1; p=quarantine; pct=100"'
                    ],
                }
            )
            result = _check_dmarc("example.com")

        assert result["present"] is True
        assert result["policy"] == "quarantine"
        assert result["finding"] is None


# ---------------------------------------------------------------------------
# SA-DNS-005: dmarc_none → DMARC_MONITOR_ONLY warning
# ---------------------------------------------------------------------------


class TestDmarcNone:
    def test_dmarc_p_none_produces_dmarc_policy_none_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("_dmarc.example.com", "TXT"): [
                        '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'
                    ],
                }
            )
            result = _check_dmarc("example.com")

        assert result["finding"] == "dmarc_policy_none"


# ---------------------------------------------------------------------------
# SA-DNS-006: missing_dmarc → DMARC_MISSING (authoritative absence)
# ---------------------------------------------------------------------------


class TestMissingDmarc:
    def test_no_dmarc_record_produces_missing_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("_dmarc.example.com", "TXT"): [],
                }
            )
            result = _check_dmarc("example.com")

        assert result["present"] is False
        assert result["finding"] == "missing_dmarc"
        assert result["collection_status"] == CollectionStatus.COMPLETE.value


# ---------------------------------------------------------------------------
# SA-DNS-007: valid_dkim → DKIM_PRESENT (selector found, record valid)
# ---------------------------------------------------------------------------


class TestValidDkim:
    def test_known_selector_found_produces_no_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("google._domainkey.example.com", "TXT"): [
                        '"v=DKIM1; k=rsa; p=MIIBIjANBg..."'
                    ],
                }
            )
            result = _check_dkim("example.com", ["google"])

        assert "google" in result["selectors_found"]
        assert result["finding"] is None, (
            "Known selector found with valid DKIM record must produce no finding."
        )


# ---------------------------------------------------------------------------
# SA-DNS-008: CRITICAL — unknown_dkim_selector does NOT imply DKIM_GLOBALLY_MISSING
# ---------------------------------------------------------------------------


class TestUnknownDkimSelector:
    """CRITICAL TRUTH CONDITION: Checking an unknown DKIM selector does NOT mean
    no DKIM exists for the domain. The domain may have DKIM configured under
    a different selector not in our check list.
    """

    def test_unknown_selector_produces_no_dkim_found_not_global_missing(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("default._domainkey.example.com", "TXT"): [],
                }
            )
            result = _check_dkim("example.com", ["default"])

        assert result["finding"] == "no_dkim_found"
        assert result["selectors_found"] == [], (
            "No selector found in our check set, but this is NOT a global DKIM_MISSING claim."
        )

    def test_unknown_selector_scan_domain_does_not_claim_dkim_globally_missing(self):
        """The full scan_domain output must not use a finding type claiming global absence."""
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 -all"'],
                    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
                    ("default._domainkey.example.com", "TXT"): [],
                    ("google._domainkey.example.com", "TXT"): [],
                    ("selector1._domainkey.example.com", "TXT"): [],
                    ("selector2._domainkey.example.com", "TXT"): [],
                    ("k1._domainkey.example.com", "TXT"): [],
                    ("mail._domainkey.example.com", "TXT"): [],
                    ("dkim._domainkey.example.com", "TXT"): [],
                    ("example.com", "MX"): ['"10 mail.example.com."'],
                    ("example.com", "DNSKEY"): [],
                }
            )
            result = scan_domain("example.com")

        finding_types = [f["type"] for f in result["findings"]]
        assert "dkim_globally_absent" not in finding_types
        if "no_dkim_found" in finding_types:
            dkim_findings = [
                f for f in result["findings"] if f["type"] == "no_dkim_found"
            ]
            assert len(dkim_findings) >= 1


# ---------------------------------------------------------------------------
# SA-DNS-009: CRITICAL — dnskey_present does NOT mean DNSSEC_CHAIN_VALIDATED
# ---------------------------------------------------------------------------


class TestDnssecObservation:
    def test_dnskey_present_does_not_claim_chain_validated(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "DNSKEY"): ['"257 3 13 (some-dnskey-data)"'],
                }
            )
            result = _check_dnssec("example.com")

        assert result["enabled"] is True
        assert result["finding"] is None

    def test_dnskey_absent_produces_dnssec_not_enabled_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "DNSKEY"): [],
                }
            )
            result = _check_dnssec("example.com")

        assert result["enabled"] is False
        assert result["finding"] == "dnssec_not_enabled"


# ---------------------------------------------------------------------------
# SA-DNS-010: DEF-001 CLOSED — dns timeout does NOT produce absence findings
# ---------------------------------------------------------------------------


class TestDnsTimeout:
    """DEF-001 closed: DNS timeout → collection_status=TIMEOUT, NO findings emitted.

    Previously (pre-L14-SCAN-COMPLETENESS-001): timeout → empty records → missing_spf.
    Now: _dns_query returns DnsQueryOutcome with status=TIMEOUT →
         _check_spf returns collection_failure=True, finding=None.
    """

    def test_spf_timeout_does_not_produce_missing_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_timeout_query,
        ):
            result = _check_spf("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None, (
            "DEF-001 closed: DNS timeout must NOT produce missing_spf finding. "
            "Timeout is indeterminate, not verified absence."
        )
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value
        assert result["present"] is None

    def test_dmarc_timeout_does_not_produce_missing_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_timeout_query,
        ):
            result = _check_dmarc("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None, (
            "DEF-001 closed: DNS timeout must NOT produce missing_dmarc finding."
        )
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value

    def test_mx_timeout_does_not_produce_no_mx_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_timeout_query,
        ):
            result = _check_mx("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value

    def test_dnssec_timeout_does_not_produce_dnssec_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_timeout_query,
        ):
            result = _check_dnssec("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value

    def test_scan_domain_timeout_all_does_not_produce_findings(self):
        """When all DNS queries time out, scan_domain must produce no findings."""
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_timeout_query,
        ):
            result = scan_domain("timeout.example.com")

        assert result["findings"] == [], (
            "All-timeout scan must produce no findings — collection was indeterminate."
        )
        assert result["any_collection_failure"] is True

    def test_run_error_per_domain_does_not_propagate_findings_to_other_domains(self):
        """An error scanning one domain must not corrupt findings for other domains."""
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            call_count = [0]

            def mock_responses(name: str, rdtype: str) -> DnsQueryOutcome:
                call_count[0] += 1
                if "timeout" in name:
                    raise Exception("DNS resolution timeout")
                return DnsQueryOutcome(records=[], status=DnsQueryStatus.NO_DATA)

            mock_q.side_effect = mock_responses
            result = run(["good-domain.example.com", "timeout-domain.example.com"])

        assert result["summary"]["total_domains"] == 2
        domain_results = {r["domain"]: r for r in result["domains"]}
        assert "timeout-domain.example.com" in domain_results
        assert "error" in domain_results["timeout-domain.example.com"]


# ---------------------------------------------------------------------------
# SA-DNS-010b: SERVFAIL → collection failure, no absence findings
# ---------------------------------------------------------------------------


class TestServfail:
    def test_spf_servfail_does_not_produce_missing_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_servfail_query,
        ):
            result = _check_spf("example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None
        assert result["collection_status"] == CollectionStatus.FAILED.value

    def test_dmarc_servfail_does_not_produce_missing_finding(self):
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            side_effect=_servfail_query,
        ):
            result = _check_dmarc("example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None


# ---------------------------------------------------------------------------
# SA-DNS-011: resolver_error → collection status FAILED, no findings emitted
# ---------------------------------------------------------------------------


class TestResolverError:
    def test_exception_in_scan_domain_captured_as_error_not_findings(self):
        """When scan_domain raises an unexpected exception, the run() wrapper captures it
        and returns an error entry without emitting findings for that domain."""
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = Exception("resolver unreachable")
            result = run(["error-domain.example.com"])

        domain_result = result["domains"][0]
        assert "error" in domain_result
        assert domain_result.get("findings", []) == []


# ---------------------------------------------------------------------------
# SA-DNS-012: mx_absent → MX_MISSING finding (authoritative)
# ---------------------------------------------------------------------------


class TestMxAbsent:
    def test_no_mx_produces_no_mx_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "MX"): [],
                }
            )
            result = _check_mx("example.com")

        assert result["present"] is False
        assert result["finding"] == "no_mx"
        assert result["collection_status"] == CollectionStatus.COMPLETE.value
        assert result["collection_failure"] is False

    def test_mx_present_produces_no_finding(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "MX"): ['"10 mail.example.com."'],
                }
            )
            result = _check_mx("example.com")

        assert result["present"] is True
        assert result["finding"] is None


# ---------------------------------------------------------------------------
# SA-DNS-013: scan_domain complete — provenance fields present
# ---------------------------------------------------------------------------


class TestScanDomainProvenance:
    """scan_domain must return structured result with all evidence fields."""

    def test_scan_domain_returns_all_check_fields(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 -all"'],
                    ("_dmarc.example.com", "TXT"): [
                        '"v=DMARC1; p=reject; rua=mailto:r@example.com"'
                    ],
                    ("default._domainkey.example.com", "TXT"): [
                        '"v=DKIM1; k=rsa; p=abc"'
                    ],
                    ("google._domainkey.example.com", "TXT"): [],
                    ("selector1._domainkey.example.com", "TXT"): [],
                    ("selector2._domainkey.example.com", "TXT"): [],
                    ("k1._domainkey.example.com", "TXT"): [],
                    ("mail._domainkey.example.com", "TXT"): [],
                    ("dkim._domainkey.example.com", "TXT"): [],
                    ("example.com", "MX"): ['"10 mail.example.com."'],
                    ("example.com", "DNSKEY"): ['"257 3 13 abc"'],
                }
            )
            result = scan_domain("example.com")

        assert "spf" in result
        assert "dmarc" in result
        assert "dkim" in result
        assert "mx" in result
        assert "dnssec" in result
        assert "findings" in result
        assert "collection_status" in result
        assert result["domain"] == "example.com"


# ---------------------------------------------------------------------------
# SA-DNS-014: DEF-001 — dns.resolver.LifetimeTimeout now produces TIMEOUT, not missing
# ---------------------------------------------------------------------------


class TestDnsResolverTimeoutClass:
    """DEF-001 closed: dns.resolver.LifetimeTimeout → DnsQueryOutcome(TIMEOUT) →
    collection_failure=True, no missing-record finding emitted.
    """

    def test_dns_resolver_timeout_returns_timeout_outcome(self):
        """dns.resolver.LifetimeTimeout is now caught specifically and returns
        DnsQueryOutcome(status=TIMEOUT). Not a list, and not empty-list-as-absence.
        """
        import dns.resolver

        with patch("dns.resolver.resolve", side_effect=dns.resolver.LifetimeTimeout):
            from services.connectors.dns_email.runner import _dns_query

            result = _dns_query("timeout-domain.example.com", "TXT")

        assert isinstance(result, DnsQueryOutcome), (
            "_dns_query must return DnsQueryOutcome, not a list."
        )
        assert result.status == DnsQueryStatus.TIMEOUT, (
            "dns.resolver.LifetimeTimeout must map to DnsQueryStatus.TIMEOUT, "
            "not to empty records (which implied absence)."
        )
        assert result.records == []

    def test_spf_check_on_dns_timeout_does_not_emit_missing_finding(self):
        """DEF-001 closed: DNS timeout → no missing_spf finding, collection_status=TIMEOUT."""
        import dns.resolver

        with patch("dns.resolver.resolve", side_effect=dns.resolver.LifetimeTimeout):
            result = _check_spf("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None, (
            "DEF-001 closed: DNS timeout must NOT produce missing_spf. "
            "Timeout is indeterminate collection, not verified record absence."
        )
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value
        assert "collection_status" in result, (
            "DEF-001 closed: collection_status field must be present in _check_spf result."
        )

    def test_dmarc_check_on_dns_timeout_does_not_emit_missing_finding(self):
        """DEF-001 closed: DNS timeout → no missing_dmarc finding."""
        import dns.resolver

        with patch("dns.resolver.resolve", side_effect=dns.resolver.LifetimeTimeout):
            result = _check_dmarc("timeout-domain.example.com")

        assert result["collection_failure"] is True
        assert result["finding"] is None, (
            "DEF-001 closed: DNS timeout must NOT produce missing_dmarc."
        )
        assert result["collection_status"] == CollectionStatus.TIMEOUT.value


# ---------------------------------------------------------------------------
# SA-DNS-015: collection_status propagated in run() summary
# ---------------------------------------------------------------------------


class TestRunCollectionStatus:
    def test_complete_scan_has_complete_status(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.side_effect = _mock_dns_query_factory(
                {
                    ("example.com", "TXT"): ['"v=spf1 -all"'],
                    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
                    ("example.com", "MX"): ['"10 mx.example.com."'],
                    ("example.com", "DNSKEY"): [],
                }
            )
            result = run(["example.com"])

        assert result["collection_status"] == CollectionStatus.COMPLETE.value

    def test_timeout_domain_produces_partial_status(self):
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            call_num = [0]

            def mixed_response(name: str, rdtype: str) -> DnsQueryOutcome:
                call_num[0] += 1
                if "timeout" in name:
                    return DnsQueryOutcome(records=[], status=DnsQueryStatus.TIMEOUT)
                return DnsQueryOutcome(records=[], status=DnsQueryStatus.NO_DATA)

            mock_q.side_effect = mixed_response
            result = run(["good.example.com", "timeout.example.com"])

        assert result["collection_status"] == CollectionStatus.PARTIAL.value
        assert result["summary"]["domains_with_collection_failures"] == 1
