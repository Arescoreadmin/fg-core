# L14-SCAN-COMPLETENESS-001 — Scanner Collection Completeness

**Closed by**: PR #810 (L14-SCAN-COMPLETENESS-001)
**Effective**: 2026-11-07
**Status**: IMPLEMENTED
**FVA gate**: FVA-04 Coverage Transparency

---

## Purpose

This document records the design decisions, defect closures, and verification criteria
for the L14-SCAN-COMPLETENESS-001 implementation. It is the authoritative reference for
why each scanner's collection status semantics are defined as they are.

---

## Canonical CollectionStatus Enum

`services/connectors/collection_status.py` defines the shared status vocabulary:

| Status | Meaning |
|--------|---------|
| `COMPLETE` | All addressable resources were collected. |
| `PARTIAL` | Some resources collected; others skipped (e.g., page cap hit). |
| `DENIED` | Access was refused (HTTP 403/401 or equivalent). |
| `TIMEOUT` | Collection timed out before completing. |
| `TRUNCATED` | Collection capped at an internal limit; not all resources scanned. |
| `FAILED` | Collection failed with an error (non-access-denial). |
| `CANCELLED` | Collection was stopped by a cancellation signal. |
| `NOT_ASSESSED` | Collection was not attempted for this source/domain. |
| `UNKNOWN` | Status cannot be determined (e.g., no scanner records exist). |

**Precedence order** (worst-first): FAILED < DENIED < TIMEOUT < CANCELLED < TRUNCATED < PARTIAL < NOT_ASSESSED < UNKNOWN < COMPLETE

This precedence is used by `AssessmentCoverageSummary.overall_collection_status`.

---

## DEF-001 — DNS Timeout Producing Absence Findings (CLOSED)

**Root cause**: `_dns_query()` in `services/connectors/dns_email/runner.py` had a bare
`except Exception: return []`. A DNS timeout (LifetimeTimeout) returned `[]` — the same
value as authoritative absence (NXDOMAIN or NoAnswer). The SPF/DMARC checks could not
distinguish "record genuinely absent" from "query failed to reach authoritative server."

**Fix**: `_dns_query()` now returns `DnsQueryOutcome(records, status)`. The status is
one of `DnsQueryStatus.{SUCCESS, NO_DATA, NXDOMAIN, TIMEOUT, SERVFAIL, REFUSED,
RESOLVER_ERROR, MALFORMED, UNSUPPORTED}`.

`DNS_COLLECTION_FAILURE_STATUSES` includes all statuses where collection failed:
`{TIMEOUT, SERVFAIL, REFUSED, RESOLVER_ERROR, MALFORMED, UNSUPPORTED}`.

`DNS_AUTHORITATIVE_ABSENCE_STATUSES` includes statuses that affirmatively confirm
record absence: `{NO_DATA, NXDOMAIN}`.

Each check function (`_check_spf`, `_check_dmarc`, etc.) calls `_collection_failed()`
and returns `collection_failure=True, present=None` when collection failed. The
`scan_domain()` function only emits findings when `not check.get("collection_failure")`.

**Adversarial test coverage**: `tests/test_scan_completeness/test_def001_dns_timeout.py`
(parametrized over 5 failure statuses × 4 record types = 20 adversarial tests).

---

## DEF-002 — Endpoint Timestamp and Encryption Defaults (CLOSED)

**Root cause (timestamp)**: `is_stale` was computed by comparing `approximateLastSignInDateTime`
to a cutoff. When the field was `""` (empty string), Python's falsy evaluation skipped
the comparison and left `is_stale=False` — incorrectly classifying the device as recent.

**Root cause (encryption)**: `bool(intune.get("isEncrypted", True))` defaulted `is_encrypted`
to `True` when no Intune record existed. Absence of data was treated as confirmed encryption.

**Fix (timestamp)**: `_classify_timestamp(raw, stale_cutoff) -> (EndpointTimestampStatus, bool | None)`:
- `None` or `""` → `(ABSENT, None)` — INDETERMINATE
- Unparseable string → `(INVALID, None)` — INDETERMINATE
- Valid ISO 8601 → `(KNOWN, bool)` — deterministic

`is_stale=None` is the indeterminate marker. It must not trigger a stale_devices finding.

**Fix (encryption)**: Missing Intune record → `encryption_status="UNKNOWN"`. Explicit
`isEncrypted=True` → `"encrypted"`. Explicit `isEncrypted=False` → `"unencrypted"` and
triggers an `endpoint.unencrypted_devices` finding. 403 on Intune → `intune_collection_status=DENIED`
and no unencrypted_devices finding.

**Adversarial test coverage**: `tests/test_scan_completeness/test_def002_endpoint_timestamp.py`
(31 tests covering `_classify_timestamp()`, runner integration, and encryption defaults).

---

## Scanner Collection Status Summary

### DNS Email (`services/connectors/dns_email/runner.py`)
- Per-domain `collection_status` in each check result
- Aggregate `collection_status` in `run()` output: COMPLETE (zero failures), PARTIAL (some), FAILED (all)
- `domains_with_collection_failures` count in `summary`

### Endpoint Inventory (`services/connectors/endpoint_inventory/runner.py`)
- `collection_status`: COMPLETE/PARTIAL/FAILED
- `intune_collection_status`: COMPLETE/DENIED (403)/PARTIAL (page cap)
- `last_seen_timestamp_status` per endpoint: KNOWN/ABSENT/INVALID
- `is_stale: bool | None` per endpoint (None = INDETERMINATE)
- `encryption_status` per endpoint: "encrypted"/"unencrypted"/"UNKNOWN"
- `summary.unknown_last_seen` count

### Network Scan (`services/connectors/network_scan/runner.py`)
- `collection_status`: COMPLETE (zero errors), PARTIAL (some), FAILED (all)
- `summary.host_scan_error_count`
- `coverage_notes.port_assessment_limitation`

### Web Headers (`services/connectors/web_headers/runner.py`)
- Per-target `collection_status`: COMPLETE/DENIED/FAILED
- Findings only emitted for COMPLETE targets
- Overall `collection_status`: worst-case across targets

### SharePoint (`services/connectors/sharepoint/runner.py`)
- `collection_status`: COMPLETE / TRUNCATED (> `_MAX_SITES`) / DENIED (403)
- `coverage_notes.site_limit_note`: present when TRUNCATED
- `coverage_notes.denied_note`: present when DENIED
- No clean-finding emitted when DENIED

### OAuth Inventory (`services/connectors/oauth_inventory/runner.py`)
- Per-source: `app_registrations`, `service_principals`, `oauth2_permission_grants`
- Overall `collection_status`: worst-case across three sources
- 403/401 → DENIED per source; page cap → PARTIAL

---

## AssessmentCoverageSummary

`services/field_assessment/coverage_summary.py` provides:

- `ScannerCoverageRecord`: per-scanner coverage data (status, permissions, sampling, followup flag)
- `AssessmentCoverageSummary`: aggregates records; computes `overall_collection_status`
- `build_coverage_summary(tenant_id, engagement_id, scan_id, scanner_records)` → `AssessmentCoverageSummary`
- `to_dict()` returns `report_constraints`:

| Constraint | True when | Meaning |
|------------|-----------|---------|
| `may_claim_no_risks_found` | overall == COMPLETE | Report may say "no risks found" |
| `may_claim_fully_assessed` | overall == COMPLETE | Report may say "fully assessed" |
| `must_disclose_incomplete_scanners` | overall != COMPLETE | Report must list incomplete scanners |
| `must_surface_assessor_followup` | any record has followup_required | Report must flag assessor review items |

Per-scanner builder functions:
- `coverage_record_from_dns_result()`
- `coverage_record_from_endpoint_result()`
- `coverage_record_from_sharepoint_result()`
- `coverage_record_from_network_result()`
- `coverage_record_from_web_headers_result()`

---

## Migration

`migrations/postgres/0202_scan_collection_status.sql` adds:
- `fa_collection_status_enum` Postgres enum type
- `fa_scan_jobs.collection_status` (nullable, FK-compatible)
- `fa_scan_jobs.collection_summary` JSONB
- `fa_normalized_findings.collection_status` (nullable)
- `CREATE INDEX CONCURRENTLY IF NOT EXISTS` indexes on both columns

All additions are nullable and non-breaking. No existing data is migrated.

---

## Test Coverage

| Suite | Tests | Coverage |
|-------|-------|----------|
| `tests/test_scan_completeness/test_collection_status.py` | ~20 | Enum, DnsQueryStatus, builders, CollectionOutcome |
| `tests/test_scan_completeness/test_def001_dns_timeout.py` | ~25 | DEF-001 — 5 failure statuses × SPF/DMARC/MX/DNSSEC + run() |
| `tests/test_scan_completeness/test_def002_endpoint_timestamp.py` | ~30 | DEF-002 — timestamp classification, encryption defaults |
| `tests/test_scan_completeness/test_coverage_summary.py` | ~25 | Summary aggregation, report_constraints, builder functions |
| `tests/test_scan_completeness/test_sharepoint_collection.py` | ~8 | SharePoint TRUNCATED/DENIED/COMPLETE |
| **Total** | **~111** | All pass |
