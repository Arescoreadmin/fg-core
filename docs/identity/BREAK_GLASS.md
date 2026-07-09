# Break-Glass Emergency Access

`BreakGlassAuthority` in `api/identity_governance/break_glass.py` implements
the FrostGate emergency access workflow. Every request is:

- **Reason-required** — an empty or whitespace-only reason raises `ValueError`.
- **Duration-bounded** — `duration_seconds > 0` and
  `duration_seconds <= MAX_BREAK_GLASS_DURATION_SECONDS` (4 hours). Exceeding
  the ceiling raises `ValueError`.
- **Approval-gated** — the requester cannot approve their own request.
  `approver != requested_by` is enforced.
- **Self-expiring** — reads that occur past `expires_at` transition the
  request to `EXPIRED` and emit a `BREAK_GLASS_EXPIRED` timeline event.
- **Revocable** — an admin can force-revoke any non-terminal request.
- **Timeline-emitting** — every state change (request, approve, revoke,
  expire) emits an event on the injected `IdentityTimeline` — so break-glass
  usage is always auditable in hash-chained form.
- **Tenant-scoped** — approval and revocation reject cross-tenant lookups
  with `ValueError`.

## Status machine

```
PENDING -> APPROVED = ACTIVE -> EXPIRED
                        \
                         -> REVOKED
```

`APPROVED` is a transient state; on successful `approve()` the request is
written back as `ACTIVE` with `approver`, `approved_at`, and `expires_at`
populated.

## Audit requirements

All break-glass state transitions emit `IdentityTimelineEvent` records with:

- `BREAK_GLASS_REQUESTED` at request time
- `BREAK_GLASS_APPROVED` at approval
- `BREAK_GLASS_EXPIRED` on revoke or elapsed-duration expiry

The event details include `request_id`, `capability`, `duration_seconds`,
and (for approval) `expires_at`. Reasons and requester identity are stored
on the `BreakGlassRequest` record itself.

## Max duration

`MAX_BREAK_GLASS_DURATION_SECONDS = 14400` (4 hours). This is a hard
compile-time ceiling — no configuration override exists at runtime. Longer
justified access must be re-requested when the previous grant expires.

## No permanent mutations

Approvals and revocations never write to the underlying identity, role, or
capability tables. Break-glass access is a runtime authorization overlay
consulted at policy-evaluation time; it disappears without side effects
when the grant expires.
