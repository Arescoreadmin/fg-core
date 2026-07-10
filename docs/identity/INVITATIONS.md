# Invitation Flow & Token Security

## Invitation Flow (ASCII)

```
Admin                    System                      Invitee
  │                        │                            │
  │── POST /admin/users/invite ─►│                     │
  │                        │                            │
  │                    generate raw_token (secrets.token_urlsafe(32))
  │                    store token_hash = SHA-256(raw_token)
  │                    create Invitation record (PENDING)
  │                    create IdentityRecord (INVITED)
  │                        │                            │
  │◄─ {invitation_token, invitation_id, subject} ──────│
  │                        │                            │
  │ [admin delivers raw_token to invitee out-of-band]   │
  │──────────── raw_token ─────────────────────────────►│
  │                        │                            │
  │                        │◄── POST /invitations/accept {token} ─┤
  │                        │                            │
  │                    SHA-256(token) → lookup by hash  │
  │                    validate: PENDING, not expired,  │
  │                              not revoked            │
  │                    set status = ACCEPTED            │
  │                        │                            │
  │                        │──► {status: ACCEPTED} ────►│
```

## Token Security Model

- **Raw token**: `secrets.token_urlsafe(32)` — 256 bits of entropy, 43 base64url chars.
- **Stored**: Only `SHA-256(raw_token)` is stored in the database. The raw token is returned once and then discarded.
- **Lookup**: `get_by_token_hash(sha256(raw_token))` — constant-time hash comparison.
- **Never logged**: The raw token is never written to logs, audit records, or timeline events.

## Replay Protection

Once an invitation is `ACCEPTED`:
- The `token_hash` still exists in the database, but `status = ACCEPTED`.
- Any subsequent call to `accept_invitation(raw_token)` finds the ACCEPTED invitation and raises `InvitationAlreadyUsedError`.
- There is no "delete on use" — the record is preserved for audit purposes.

## Expiry

- Default expiry: **7 days** from invitation time.
- Maximum expiry: **30 days** (enforced by `MAX_EXPIRY_DAYS`).
- Expiry is checked on `accept_invitation()` — invitations are not eagerly expired.
- A background job or on-access check can call `expire_pending()` to mark expired invitations.

## Reissue Workflow

```
Admin                    System
  │                        │
  │── POST /admin/invitations/{id}/reissue ─►│
  │                        │
  │                    REVOKE old invitation (status = REVOKED)
  │                    CREATE new invitation (new token, new expiry)
  │                        │
  │◄── {new invitation_token, new invitation_id} ──────│
```

After reissue, the old token raises `InvitationRevokedError` on accept.

## Audit Trail

Every invitation lifecycle event is recorded:
- `invite_user()` → `AdminAuditRecord` with `action=INVITE`
- `accept_invitation()` → `Invitation.accepted_at` + `accepted_by`
- `revoke_invitation()` → `Invitation.revoked_at` + `revoked_by`
- `reissue_invitation()` → revoke old + new invite audit records

Timeline events are also emitted for all invitation actions.
