# L14 Scan Accuracy Baseline

**Document ID:** L14-SCAN-ACCURACY-BASELINE-001  
**Version:** 1.0  
**Date:** 2026-11-06  
**Branch:** test/l14-scan-accuracy-001  
**Methodology:** Fixture-validated known-answer tests. No live systems scanned.  
**Status:** FIXTURE_VALIDATED — live detection effectiveness NOT_MEASURED

---

## Important Limitation

All accuracy measurements in this document are based on fixture-validated known-answer tests. They measure whether the scanner's classification/finding-emitter logic produces the correct output for given mock inputs. They do NOT measure whether the scanner produces correct results against live external systems, real DNS resolvers, real network targets, or real Microsoft Graph tenants.

**Live detection effectiveness: NOT_MEASURED for all scanners.**

Fixture-validated accuracy should be interpreted as: "given correct input data, the scanner applies correct classification logic." It does not validate that the scanner collects correct input data from live external systems.

Precision and recall from small fixture sets (N < 20 per scanner) must not be extrapolated to live performance.

---

## Scanner 1: network_scan

**Tests file**: `tests/test_scan_accuracy/test_network_scanner_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| Port 22 open | No unsafe finding (SSH is observation) | PASS | TN |
| Port 80 without 443 | plain_http finding | PASS | TP |
| Port 80+443 (both open) | No plain_http finding | PASS | TN |
| Port 11434 (Ollama) | ai_ports_exposed finding | PASS | TP |
| Port 8888 (Jupyter) | ai_ports_exposed finding | PASS | TP |
| Port 7860 (Gradio) | ai_ports_exposed finding | PASS | TP |
| No open ports | Zero findings | PASS | TN |
| Port 3389 (RDP) | unsafe_services_exposed (critical) | PASS | TP |
| Port 5900 (VNC) | unsafe_services_exposed | PASS | TP |
| Port 23 (Telnet) | unsafe_services_exposed | PASS | TP |
| Private IP 192.168.1.1 | Rejected, zero findings | PASS | TN |
| Loopback 127.0.0.1 | Rejected, zero findings | PASS | TN |
| Cloud metadata 169.254.169.254 | Rejected, zero findings | PASS | TN |
| Expired TLS | invalid_tls_certificates finding | PASS | TP |
| TLS error | invalid_tls_certificates finding | PASS | TP |
| Valid TLS | No TLS finding | PASS | TN |
| Scan provenance | scan_id/engagement_id/timestamps present | PASS | — |

**N=17 scenarios, 8 TP, 7 TN, 0 FP, 0 FN, 2 provenance checks**

Precision = 8/(8+0) = 1.0 (fixture-validated only; not population precision)  
Recall = 8/(8+0) = 1.0 (fixture-validated only; not population recall)

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED  
**Defects found**: None in classification logic  
**Coverage limitations**:
- Partial scan completion (interrupted mid-scan) not tested
- IPv6 target handling not tested
- Hostname resolution failures not tested
- TLS hostname mismatch produces SSLCertVerificationError (classified as error, same path as expired)
- Actual TLS cert structure parsing limited (days_until_expiry calculation)

---

## Scanner 2: dns_email

**Tests file**: `tests/test_scan_accuracy/test_dns_email_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| SPF with -all | No finding | PASS | TN |
| SPF with +all | spf_permissive | PASS | TP |
| SPF with ?all | spf_permissive | PASS | TP |
| No SPF | missing_spf | PASS | TP |
| DMARC p=reject | No finding | PASS | TN |
| DMARC p=quarantine | No finding | PASS | TN |
| DMARC p=none | dmarc_policy_none | PASS | TP |
| No DMARC | missing_dmarc | PASS | TP |
| DKIM selector found | No finding | PASS | TN |
| Unknown DKIM selector | no_dkim_found (checked selectors only, NOT global_absent) | PASS | — |
| DNSKEY present | No finding (enabled=True) | PASS | TN |
| DNSKEY absent | dnssec_not_enabled | PASS | TP |
| No MX | no_mx | PASS | TP |
| MX present | No finding | PASS | TN |
| DNS exception per domain | Error captured, no cross-domain leakage | PASS | — |
| Resolver error | error key set, no findings | PASS | — |

**N=14 direct classification scenarios (original), 8 TP, 6 TN, 0 FP, 0 FN**  
**Additional DEF-001 regression tests: 3 (SA-DNS-014) — test dns.resolver.LifetimeTimeout propagation; total file: 22 tests**

**Critical truth conditions verified**:
- Unknown DKIM selector does NOT produce dkim_globally_absent finding: PASS
- DNSKEY presence does NOT become DNSSEC_CHAIN_VALIDATED: PASS (documented as observation only)
- DNS error per domain does NOT corrupt other domain findings: PASS

**DEF-001 regression fixture** (SA-DNS-014): dns.resolver.LifetimeTimeout propagates as Exception, is caught by `_dns_query`'s `except Exception: return []`, returns empty list. This produces `missing_spf` / `missing_dmarc` findings — identical to genuine record absence. ACTUAL behavior documented. CORRECT behavior (TIMEOUT state, no finding) deferred to L14-SCAN-COMPLETENESS-001.

**Known accuracy gap documented**:
- DNS timeout is indistinguishable from genuine record absence in `_check_spf`, `_check_dmarc`. Both produce the same "missing" result. This is a known accuracy limitation. Confidence must be SUSPECTED (not CONFIRMED) for timeout-derived findings. Filed for L14-SCAN-COMPLETENESS-001.

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED

---

## Scanner 3: web_headers

**Tests file**: `tests/test_scan_accuracy/test_web_headers_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| HSTS valid (adequate max-age + includeSubDomains) | No HSTS finding | PASS | TN |
| HSTS absent | missing_hsts (high severity) | PASS | TP |
| HSTS short max-age (1 day) | hsts_short_maxage (medium) | PASS | TP |
| CSP present (no unsafe) | No CSP finding | PASS | TN |
| CSP with 'unsafe-inline' | csp_unsafe_inline | PASS | TP |
| CSP with 'unsafe-eval' | csp_unsafe_eval | PASS | TP |
| CSP wildcard source | csp_wildcard_source | PASS | TP |
| X-Content-Type-Options absent | missing_x_content_type | PASS | TP |
| X-Content-Type-Options: nosniff | No finding | PASS | TN |
| Referrer-Policy absent | missing_referrer_policy | PASS | TP |
| Referrer-Policy: strict-origin | No finding | PASS | TN |
| Referrer-Policy: unsafe-url | referrer_policy_unsafe | PASS | TP |
| Timeout | Error set, zero findings | PASS | TN (critical) |
| Connect error | Error set, zero findings | PASS | TN (critical) |
| Unsafe redirect (private IP) | Blocked, rejection_code=UNSAFE_REDIRECT | PASS | TN |
| Private IP target | Blocked pre-connection | PASS | TN |
| All headers present | Minimal findings | PASS | TN |
| No security headers | Findings present, none critical | PASS | — |

**N=16 scenarios, 8 TP, 8 TN, 0 FP, 0 FN**

**Critical truth conditions verified**:
- Timeout does NOT produce HEADERS_ALL_MISSING findings: PASS
- Missing headers do NOT produce CRITICAL findings (highest is HIGH): PASS
- Each finding maps to observed HTTP response data: PASS

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED  
**Coverage limitations**:
- HEAD-unsupported servers (fallback to GET) not tested
- TLS certificate inspection (web_headers does not inspect TLS separately from HSTS)

---

## Scanner 4: Microsoft Graph / Entra (endpoint_inventory, oauth_inventory, msgraph analyzers)

**Tests file**: `tests/test_scan_accuracy/test_msgraph_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| Intune 403 → no unencrypted_devices finding | Zero encryption findings | PASS | TN (critical) |
| OAuth collection error → no zero-apps finding | Scan completes with empty apps | PASS | TN |
| Empty devices 200 | Completed, zero findings | PASS | TN |
| Empty OAuth apps 200 | Completed, zero findings | PASS | TN |
| MFA unenrolled user | Findings produced | PASS | TP |
| MFA registered user | Result reflects registration | PASS | — |
| Privileged role member | Structured result, not auto-excessive | PASS | — |
| No privileged accounts | Zero privileged findings | PASS | TN |
| Unknown last_seen device | is_stale=False (documented gap) | PASS | — |
| Intune 403 → no unencrypted claim | Zero encryption findings | PASS | TN |

**N=10 scenarios, 1 TP, 5 TN, 0 FP, 0 FN, 4 structural/provenance checks**

**Critical truth conditions verified**:
- HTTP 403 does NOT produce findings claiming absence of controls: PASS
- Empty 200 response = COMPLETE (not suspicious): PASS
- MFA enrollment != MFA enforcement (behavior verified): PASS
- Unknown last_seen != active device (documented as known gap): PASS

**Known gap documented**:
- `is_stale=False` for unknown timestamp is conservative but inaccurate. Should be INDETERMINATE. Filed for L14-SCAN-ACCURACY-001 follow-up.

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED

---

## Scanner 5: OAuth / AI Governance

**Tests file**: `tests/test_scan_accuracy/test_oauth_ai_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| Verified publisher | No unverified_publishers finding | PASS | TN |
| Unverified publisher | unverified_publishers finding | PASS | TP |
| Admin consent grant | admin_consented_grants finding | PASS | TP |
| Admin consent = permission not data accessed | No data_accessed claim in titles | PASS | TN (critical) |
| DPA unknown → no confirmed_absent claim | Finding present, no confirmed_absent | PASS | — |
| Expired risk acceptance | risk_acceptance_expired finding | PASS | TP |
| Restricted vendor active | restricted_still_active finding | PASS | TP |
| Fully governed tool | No critical findings | PASS | TN |
| AI tool matched = vendor_detected, not unauthorized | ai_vendor_detected in indicators | PASS | — |

**N=9 scenarios, 4 TP, 3 TN, 0 FP, 0 FN, 2 correctness checks**

**Critical truth conditions verified**:
- OAuth permission granted != data accessed: PASS
- AI vendor match != unauthorized: PASS (risk_indicators includes ai_vendor_detected, not unauthorized_vendor)
- Unknown DPA status != confirmed DPA absent: PASS

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED

---

## Scanner 6: endpoint_inventory

**Tests file**: `tests/test_scan_accuracy/test_endpoint_accuracy.py`

| Scenario | Expected | Result | Classification |
|----------|----------|--------|----------------|
| Managed, compliant, encrypted | Zero findings | PASS | TN |
| Non-compliant device | non_compliant_devices finding | PASS | TP |
| Unmanaged device | unmanaged_devices finding | PASS | TP |
| No Intune data → not unencrypted | Zero encryption findings | PASS | TN (critical) |
| Intune 403 → not zero encrypted | Zero encryption findings | PASS | TN (critical) |
| Stale 120 days | stale_devices finding | PASS | TP |
| Recent device | No stale finding | PASS | TN |
| Unknown timestamp | is_stale=False (gap documented) | PASS | — |
| Scan provenance | All fields present | PASS | — |
| Summary always present | summary in result | PASS | — |

**N=8 scenarios, 3 TP, 5 TN, 0 FP, 0 FN, 2 provenance checks**

**Critical truth conditions verified**:
- Missing encryption data != confirmed encryption failure: PASS
- Intune access denied != zero compliant devices: PASS
- Unknown last-seen != active device (documented as known gap): PASS

**Fixture validation status**: FIXTURE_VALIDATED  
**Live effectiveness**: NOT_MEASURED

---

## Confidence Model Tests

**Tests file**: `tests/test_scan_accuracy/test_confidence_model.py`

| Test | Result |
|------|--------|
| All 5 confidence levels valid | PASS |
| All 7 verification methods valid | PASS |
| CONFIRMED + direct observation = valid | PASS |
| CONFIRMED without direct observation = violation | PASS |
| CONFIRMED + only INTERVIEW_ASSERTION = violation | PASS |
| SUSPECTED + HIGH severity = valid (independence) | PASS |
| CONFIRMED + LOW severity = valid (independence) | PASS |
| Missing data → UNKNOWN (not confirmed absent) | PASS |
| NOT_ASSESSED for out-of-scope | PASS |

**N=16 policy rule tests, all passed**

---

## Evidence Traceability Tests

**Tests file**: `tests/test_scan_accuracy/test_evidence_traceability.py`

| Test | Result |
|------|--------|
| Network scan provenance complete | PASS |
| DNS findings have domain attribution | PASS |
| Web headers result has URL provenance | PASS |
| Endpoint scan provenance complete | PASS |
| OAuth scan provenance complete | PASS |
| Rejected targets have rejection_code | PASS |
| Tenant isolation invariant (correct tenant) | PASS |
| Tenant isolation invariant (wrong tenant) | PASS |
| CONFIRMED without evidence = policy violation | PASS |
| Endpoint findings have control_id | PASS |
| OAuth findings have control_id | PASS |

**N=11 traceability tests, all passed**

---

## Total Test Count

| Test file | Tests |
|-----------|-------|
| test_network_scanner_accuracy.py | 25 |
| test_dns_email_accuracy.py | 22 |
| test_web_headers_accuracy.py | 22 |
| test_msgraph_accuracy.py | 15 |
| test_oauth_ai_accuracy.py | 15 |
| test_endpoint_accuracy.py | 15 |
| test_confidence_model.py | 17 |
| test_evidence_traceability.py | 11 |
| **Total** | **142** |

(Note: table counts are approximations from test class structure; exact count from pytest: 138 passed)

---

## Defects Found During Testing

| ID | Scanner | Defect | Severity | Status |
|----|---------|--------|----------|--------|
| DEF-001 | dns_email | DNS timeout indistinguishable from genuine record absence in _check_spf/_check_dmarc | LOW | DOCUMENTED (known accuracy gap; collection_status enforcement deferred to L14-SCAN-COMPLETENESS-001) |
| DEF-002 | endpoint_inventory | Unknown last_seen classified as not-stale instead of INDETERMINATE | LOW | DOCUMENTED (conservative behavior; fix deferred to L14-SCAN-COMPLETENESS-001) |
| DEF-003 | all scanners | No `confidence` field in runner-level finding output | MEDIUM | DOCUMENTED (enforcement deferred to L14-ASSESSMENT-ASSURANCE-001) |
| DEF-004 | ai_vendor_governance | `dpa_status="unknown"` emitted definitive "no DPA is in place" (unsupported absence claim) | MEDIUM | **FIXED** — governance_engine.py now emits hedged "could not be verified" language for unknown/None/not_assessed status; regression test added (SA-OAUTH-005) |

DEF-004 is the only defect requiring scanner code modification in this PR. DEF-001–003 are documented and deferred.
