# L14 Scan Execution Safety and Scope Enforcement

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Field safety analysis for all scanners: SSRF protection, target validation, rate limiting, emergency stop capability, and offline operation assessment.

---

## SSRF Protection Architecture

**Central authority:** `services/connectors/safe_target_validator.py` — `SafeTargetValidationService`

The validator enforces 6 layers on every call to `validate()`:

**Layer 1 — Input normalization:** target is stripped and type-detected (url/cidr/ip/hostname)

**Layer 2 — DNS resolution:** hostnames are resolved to all IPs before any check

**Layer 3 — Private range blocking:**

IPv4 blocked ranges (from source):
- 0.0.0.0/8 (This network)
- 10.0.0.0/8 (RFC1918 Private)
- 100.64.0.0/10 (CGNAT, RFC6598)
- 127.0.0.0/8 (Loopback)
- 169.254.0.0/16 (Link-local / APIPA / Cloud metadata)
- 172.16.0.0/12 (RFC1918 Private)
- 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24 (IETF assignments)
- 192.168.0.0/16 (RFC1918 Private)
- 198.18.0.0/15 (Benchmarking)
- 198.51.100.0/24, 203.0.113.0/24 (Documentation TEST-NET-2/3)
- 224.0.0.0/4 (Multicast)
- 233.252.0.0/24 (Documentation MCAST-TEST)
- 240.0.0.0/4 (Future use)
- 255.255.255.255/32 (Broadcast)

IPv6 blocked ranges: ::1/128, ::ffff:0:0/96 (IPv4-mapped including private), fc00::/7, fe80::/10, ff00::/8, and others.

**Layer 4 — Cloud metadata endpoint protection:**
- 169.254.169.254 (AWS IMDSv1/v2, Azure IMDS, GCP, DigitalOcean)
- fd00:ec2::254 (AWS IPv6 IMDSv2)
- 100.100.100.200 (Alibaba Cloud ECS metadata)
- metadata.google.internal, metadata.gce.internal
- metadata.azure.com, metadata.azure.internal
- instance-data (DigitalOcean legacy)

**Layer 5 — DNS rebinding protection:** ALL resolved IPs must pass. If a hostname resolves to both a public and a private IP, the validation fails. The first-safe/second-unsafe attack vector is explicitly addressed.

**Layer 6 — CIDR host validation:** Every host in a CIDR with 16 or fewer addresses is individually validated. For larger CIDRs, the network and broadcast addresses are checked to detect fully-private CIDR submissions.

**IPv4-mapped IPv6 protection:** IPv6 addresses with embedded IPv4 (::ffff:10.0.0.1) are unwrapped and the IPv4 portion is checked against the IPv4 blocklist.

---

## Defence-in-Depth: Runner-Level Validation

Both `network_scan` and `web_headers` runners import and instantiate `SafeTargetValidationService` directly:

```python
# network_scan/runner.py
_validator = SafeTargetValidationService()
# Called in _expand_targets() before ANY socket connection

# web_headers/runner.py
_validator = SafeTargetValidationService()
# Called in scan_target() before connection + in _follow_redirects_safely() per redirect hop
```

This means the validation is enforced even if the runner is called directly (not via the API layer), providing defence-in-depth.

---

## Redirect Chain Safety

The web_headers runner disables automatic redirect following (`follow_redirects=False` on the httpx client) and manually re-validates every redirect Location header:

```python
def _follow_redirects_safely(client, initial_url):
    for _ in range(_MAX_REDIRECT_HOPS):  # max 5 hops
        resp = client.head(current_url, follow_redirects=False)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp, None
        location = resp.headers.get("location", "")
        next_url = urljoin(current_url, location)
        result = _validator.validate(next_url, target_type="url")
        if not result.ok:
            return resp, f"redirect to {next_url!r} blocked: ..."
```

This prevents the open-redirect SSRF pattern where the initial target is public but redirects to an internal endpoint.

---

## Rate Limiting

API-layer rate limits enforced in `api/field_assessment.py`:

- `_MAX_CONCURRENT_JOBS_PER_ENGAGEMENT = 3`
- `_MAX_CONCURRENT_JOBS_PER_TENANT = 10`

Both limits are checked before every scan initiation. Rate-limit events are logged to `fa_scan_audit_events` with `event_type=scan.rate_limited` and rejection codes `RATE_LIMIT_ENGAGEMENT` / `RATE_LIMIT_TENANT`. HTTP 429 is returned to the caller.

**Scanner-specific limits:**
- network_scan: `_MAX_HOSTS = 50` (hard cap after CIDR expansion)
- sharepoint_onedrive: 30 sites, 3 drives/site, 100 items/drive, 15 permission checks/drive
- endpoint_inventory: pagination capped at 20 pages
- All Graph connectors: pagination capped at 20 pages

---

## Target Pre-Authorization and Persistence

Every scan target is processed through `_c6_validate_and_store_targets()` before any scan job is created:

1. `SafeTargetValidationService.validate()` is called per target
2. A `FaVerifiedTarget` row is written for EVERY target (verified and rejected)
3. `resolved_ips` (JSON), `rejection_reason`, `rejection_code`, `verified_at`, `verified_by` are stored
4. Rejected targets trigger `scan.validation_rejected` audit events with the resolved IPs
5. If ANY target is rejected, the entire scan batch is aborted

This creates a complete audit trail: an assessor can demonstrate after the fact exactly which targets were scanned, which were rejected, and why.

---

## Scan Authorization Model

The Microsoft Graph connector requires a formal `AcknowledgmentReceipt` before any scan can run. The receipt includes:

- `engagement_id` — binds the scan to a specific engagement
- `tenant_id` — the Azure AD tenant being scanned
- `scan_authorized_at` — timestamp of authorization
- `authorized_scopes` — the Graph API scopes the token covers (allowlisted against `AUTHORIZED_SCOPES` manifest)
- Receipt hash — deterministic SHA-256 of all fields

The acknowledgment system ensures that every Graph scan has a documented authorization chain before it touches client infrastructure.

---

## Emergency Stop Capability

**Current status: NOT IMPLEMENTED as an explicit endpoint.**

There is no `POST /scans/{job_id}/cancel` or `POST /engagements/{id}/emergency-stop` endpoint.

Mitigation: Scan jobs are short-lived (seconds to minutes). The rate limit system prevents runaway scan accumulation. Durable job status tracks completion/failure. However, an operator cannot actively abort an in-flight scan from the API.

**Recommendation:** Add a `PATCH /engagements/{id}/scan-jobs/{job_id}/cancel` endpoint. This is P2 for field safety compliance.

---

## Offline / Air-Gapped Capability

| Scanner | Offline Capable | Notes |
|---------|----------------|-------|
| microsoft_graph | No | Requires live Azure AD API access |
| entra_governance | No | Requires live Graph API |
| endpoint_inventory | No | Requires live Graph / Intune API |
| oauth_inventory / oauth_risk | No | Requires live Graph API |
| ai_tool_discovery | No | Requires live Graph API |
| ai_data_access_mapping | Yes | Pure computation on PR1 output |
| external_ai_risk_register | Yes | Pure computation on PR1+PR2 output |
| ai_vendor_governance | Yes | Pure computation on PR1+PR2+PR3 output |
| network_scan | Partial | Can run on-site without internet if targets are local-external; SSRF blocks purely internal |
| web_headers | Partial | Can run on-site for public URLs |
| dns_email | Partial | Requires DNS resolver access |
| sharepoint_onedrive | No | Requires live Graph API |

**AI governance chain is the most offline-resilient cluster** — once PR1 data is collected, PR2+PR3+PR4 can run purely from collected evidence.

---

## Field Safety Checklist for Assessors

Before running network_scan or web_headers in the field:

1. Obtain written authorization from client listing all target IPs/hostnames/URLs
2. Confirm targets are external-facing (SSRF controls will reject internal targets)
3. Use the `POST /engagements/{id}/scan-jobs/validate-targets` endpoint (if available) to preview which targets will be accepted/rejected before running the scan
4. Verify rate limits allow the scan (no more than 3 concurrent per engagement)
5. All targets are logged to `fa_verified_targets` — these become evidence of scope
6. Never attempt to bypass target validation — rejected targets are logged and auditable

Before running Microsoft Graph scans:

1. Obtain OAuth token with read-only scopes only
2. Generate acknowledgment receipt via `POST /engagements/{id}/msgraph/acknowledgment`
3. Confirm tenant_id matches the authorized client tenant
4. Scan authorization is recorded and audit-traceable
