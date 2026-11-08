# L14 Scan Authorization and Cancellation

**Document ID:** L14-SCAN-SAFETY-001  
**Version:** 1.0  
**Date:** 2026-11-06  
**Status:** IMPLEMENTED (synchronous runners) | ASYNC WORKER REVALIDATION DEFERRED

---

## Security Gap Closed

FrostGate's scanner dispatch had no per-engagement authorized target scope. Any publicly
routable host passed SSRF validation regardless of whether it belonged to the assessed client.
An operator with `scan.trigger` permission could use a legitimate client engagement to probe
unrelated internet-routable systems.

Root cause (from FVA-01 audit in PR #808): `SafeTargetValidationService` enforces SSRF
boundaries (RFC1918, loopback, cloud metadata). It does not enforce client authorization. No
per-engagement target scope list existed. No acknowledgment gate existed for DNS/network/web
header scanners.

---

## Authorization Model

### Scope lifecycle states

```
draft → pending_approval → approved → active → expired
                                     ↘ revoked
```

- **draft**: Created by operator; not yet enforced. Targets can be edited.
- **pending_approval**: Awaiting second-party review (optional workflow step).
- **approved**: Reviewed and approved; not yet effective (future `effective_from`).
- **active**: Enforced. `effective_from <= NOW() < expires_at` required.
- **expired**: Past `expires_at`. No longer enforced. Terminal.
- **revoked**: Explicitly revoked. No longer enforced. Terminal.

### Approval flow

1. Operator creates scope via `POST /field-assessment/engagements/{id}/scan-authorizations`
   with `authorization_ref` (reference to signed Rules of Engagement document), `approved_targets`
   (JSONB array), and `expires_at`.
2. Operator activates scope via `POST /field-assessment/engagements/{id}/scan-authorizations/{auth_id}/activate`.
3. Scanner routes check scope via `check_scan_authorized()` before dispatching any background task.
4. Operator may revoke scope at any time via `POST /field-assessment/engagements/{id}/scan-authorizations/{auth_id}/revoke`.

### Approved targets format

Each entry in `approved_targets`:
```json
{
  "target": "example.com",
  "type": "fqdn",
  "operations": ["network_scan", "web_headers", "dns_email"],
  "allow_subdomains": false
}
```

- `type`: `fqdn` | `ipv4` | `ipv6` | `cidr`
- `operations`: subset of `["network_scan", "web_headers", "dns_email"]`
- `allow_subdomains`: opt-in (default `false`). Permits `sub.example.com` only when `true`.

---

## Target Normalization Rules

All candidate and approved targets are normalized via `normalize_target()` before comparison.
Parse failure always fails closed — it never treats a malformed target as a match.

| Input type | Normalization rule |
|------------|-------------------|
| fqdn | Lowercase, strip trailing dot, validate labels (1-63 chars, `[a-z0-9-]`, no leading/trailing hyphen), reject total > 253 chars |
| ipv4 | Canonical via `ipaddress.IPv4Address.compressed` |
| ipv6 | Canonical via `ipaddress.IPv6Address.compressed`; zone IDs rejected; IPv4-mapped (`::ffff:a.b.c.d`) rejected |
| cidr | Canonical via `ipaddress.ip_network(strict=False).compressed` (host bits collapsed) |

### Key normalization invariants

- `EXAMPLE.COM` == `example.com` (case insensitive)
- `example.com.` == `example.com` (trailing dot stripped)
- `evil-example.com` != `example.com` (lookalike rejected)
- `example.com.evil.tld` != `example.com` (injection rejected)
- `::ffff:1.2.3.4` raises ValueError — not silently authorized as `1.2.3.4`
- `fe80::1%eth0` raises ValueError — zone IDs rejected

---

## Scanner Enforcement Matrix

| Scanner | Enforcement boundary | Authorization gate | SSRF gate | Notes |
|---------|---------------------|-------------------|-----------|-------|
| network_scan | Route (synchronous) | `check_scan_authorized` per target | `SafeTargetValidationService` | Background task; route-level check is sufficient |
| dns_email | Route (synchronous) | `check_scan_authorized` per domain | `SafeTargetValidationService` | Background task |
| web_headers | Route (synchronous) | `check_scan_authorized` per URL (hostname extracted) | `SafeTargetValidationService` | Background task |
| msgraph / Entra | Not extended | Existing `acknowledgment_receipt_id` gate | N/A (OAuth, not network scan) | Different identity model |
| oauth_inventory | Not extended | Existing gate | N/A | Cloud identity, not network target |
| endpoint_inventory | Not extended | Existing gate | N/A | Cloud identity |
| ai_tool_discovery | Not extended | Existing gate | N/A | Cloud identity |

**Async worker revalidation:** All three covered scanners run synchronously via FastAPI
`BackgroundTasks`. The route-level check is therefore the execution boundary. If async workers
(Celery, task queues) are introduced, a revalidation call MUST be added at the worker execution
boundary. A TODO comment is present in `api/field_assessment.py`.

---

## Cancellation State Machine

```
         cancel_scan()
queued ──────────────► cancel_requested ──► cancelled  (via confirm_scan_cancelled)
running ─────────────► cancel_requested ──► cancelled

complete  (terminal — cannot be cancelled)
failed    (terminal — cannot be cancelled)
dead_letter (terminal)
cancelled   (terminal — idempotent)
```

### Race-safety

Cancellation uses `UPDATE ... WHERE status IN ('queued', 'running') ... RETURNING status`.
If the worker completes the scan before the cancel reaches the DB, the UPDATE finds no rows
and `cancel_scan()` raises `CANCEL_TERMINAL_STATE`. This is correct: the scan completed
before the cancel request landed.

### Durability

Cancellation state is persisted in `fa_scan_jobs.cancel_requested_at`, `cancelled_at`,
`cancellation_reason`, `cancelled_by`. It survives process restarts. A new worker reading
a `cancel_requested` job MUST call `confirm_scan_cancelled()` instead of `mark_complete()`.

---

## Emergency Stop Workflow

### Activation

```
POST /field-assessment/emergency-stop
{
  "scope": "platform" | "tenant:{id}" | "engagement:{id}",
  "reason": "..."
}
```

Requires `scan.emergency_stop` permission.  
Platform scope requires `scan.emergency_stop.platform` (higher privilege).

### Effect

Any call to `check_scan_authorized()` checks `fa_scan_emergency_stops` for active stops
in the scope hierarchy (platform → tenant → engagement). An active stop at any level raises
`EMERGENCY_STOP_ACTIVE` and denies the scan.

### Clearing

The stop remains active until explicitly cleared by an authorized operator. A cleared stop
records `cleared_at` and `cleared_by` for the audit trail.

### Cross-tenant protection

A tenant-scoped stop cannot affect a different tenant. Platform-scoped stop requires higher
privilege than tenant-scoped stop.

---

## Threat Model

### Attacks closed by this PR

| Attack | Mitigation |
|--------|-----------|
| Operator probes unrelated internet host using client engagement | `check_scan_authorized` denies target not in scope |
| Operator uses expired authorization to scan | Expiry check in `check_scan_authorized` |
| Operator uses revoked authorization | Revocation check in `check_scan_authorized` |
| Cross-tenant authorization re-use | Tenant+engagement isolation in DB query and defence-in-depth check in service |
| Lookalike domain injection (`evil-example.com` ≈ `example.com`) | Exact-match normalization; allow_subdomains is opt-in |
| Subdomain scope injection via trailing dot | Trailing dot stripped before comparison |
| IPv4-mapped IPv6 bypasses IPv4 scope check | IPv4-mapped addresses raise ValueError |
| DB error permits scan | Fail-closed: any exception during authorization → denial |
| Empty approved_targets permits anything | Explicit empty-list check → denial |
| Cancelled scan resumes | CANCELLED is terminal; `confirm_scan_cancelled` is idempotent |
| Emergency stop bypassed | Checked first in `check_scan_authorized`, before authorization lookup |
| Unauthorized emergency stop activation | Permission check gates activation; cross-tenant activation denied |

### Attacks NOT closed by this PR

| Attack | Status |
|--------|--------|
| Operator registers a fraudulent Rules of Engagement reference | FVA-01 policy gap: `authorization_ref` is a free-text field. No external document signing or verification is performed. This is an operational gap, not a technical one. |
| Async worker completes scan after route-level check but before operator activates emergency stop | Deferred: synchronous runners are covered; async worker revalidation deferred to worker architecture decision |
| Cloud connector (Graph/Entra/OAuth) uses network targets outside scope | Different identity model; existing acknowledgment_receipt_id gate applies |

---

## FVA-01 Status Update

**Before this PR:** PARTIALLY_IMPLEMENTED — 5 of 9 testable criteria enforced.

**After this PR:** PARTIALLY_IMPLEMENTED — 9 of 9 testable criteria enforced.

Remaining PARTIALLY_IMPLEMENTED qualification:
- Acknowledgment receipt gate exists for MsgGraph only (DNS/network/web have scope authorization, not signed receipt)
- Async worker revalidation deferred

See `docs/assurance/FROSTGATE_VERIFIED_ASSESSMENT_STANDARD.md` for complete FVA-01 status and code references.

---

## Migration Deployment Order

1. Run `migrations/postgres/0200_fa_scan_authorization.sql`
2. Deploy updated `api/field_assessment.py` and `services/field_assessment/scan_authorization.py`
3. Create scan authorization records for each active engagement before initiating new scans

**Breaking change note:** Legacy engagements that have no `fa_scan_authorizations` record
will be blocked from new scan dispatch. Operators must create and activate an authorization
record per engagement before scans can proceed.

---

## Known Limitations and Follow-up Workstreams

1. **Async worker revalidation** (TODO in `api/field_assessment.py`): When async workers
   are introduced, `check_scan_authorized()` must be called at the start of each worker
   execution function, not just at the route level.

2. **Authorization reference verification**: `authorization_ref` is a free-text field.
   No external document signing verification is performed. A future PR should link this
   to a signed artifact in the governed delivery chain.

3. **Cloud connector scope model**: The `fa_scan_authorizations` schema supports `fqdn`,
   `ipv4`, `ipv6`, and `cidr` target types. Cloud provider targets (AWS account ID, Entra
   tenant ID) use a different identity model — not extended in this PR.

4. **Scope approval workflow**: The activation step is currently a unilateral operator
   action. A future PR should add a two-party approval flow (create → pending_approval →
   approved → activate) for high-assurance environments.

5. **L14-SCAN-INTEGRITY-001**: Runner-level content hash signatures. Deferred.

---

## Update — L14-SCAN-AUTH-HARDENING-001

Limitations 1 (async worker revalidation), 2 (authorization reference verification, now a customer receipt) and 4 (two-party approval) are addressed for network, DNS/email and web-header scanners. Also fixed:

- cross-tenant release of engagement-scoped emergency stops;
- the `fa_scan_audit_events` event-type CHECK that rejected `scan.authorization.*` and `scan.cancel.*`;
- `dead_letter` missing from the `fa_scan_jobs` status CHECK;
- non-CAS job transitions.

Details: `docs/assurance/L14_SCAN_AUTHORIZATION_HARDENING.md`.
