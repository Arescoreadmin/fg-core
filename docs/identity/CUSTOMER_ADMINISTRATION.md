# Customer Identity Administration API Reference

## Prefix

All endpoints live under `/identity`.

## Permissions

| Endpoint                                    | Method   | Required Permission   |
|---------------------------------------------|----------|-----------------------|
| `/identity/admin/users/invite`              | POST     | `user.invite`         |
| `/identity/admin/users`                     | GET      | `governance.read`     |
| `/identity/admin/users/{subject}`           | GET      | `governance.read`     |
| `/identity/admin/users/{subject}/lifecycle` | PATCH    | `tenant.configure`    |
| `/identity/admin/users/{subject}`           | DELETE   | `tenant.configure`    |
| `/identity/admin/users/{subject}/timeline`  | GET      | `governance.read`     |
| `/identity/admin/users/{subject}/devices`   | GET      | `governance.read`     |
| `/identity/admin/users/{subject}/devices/{id}` | PATCH | `tenant.configure`    |
| `/identity/admin/invitations`               | GET      | `governance.read`     |
| `/identity/admin/invitations/{id}`          | DELETE   | `tenant.configure`    |
| `/identity/admin/invitations/{id}/reissue`  | POST     | `user.invite`         |
| `/identity/admin/audit`                     | GET      | `governance.read`     |
| `/identity/admin/groups`                    | GET      | `governance.read`     |
| `/identity/admin/groups`                    | POST     | `tenant.configure`    |
| `/identity/admin/groups/{id}`               | GET      | `governance.read`     |
| `/identity/admin/groups/{id}`               | DELETE   | `tenant.configure`    |
| `/identity/admin/groups/{id}/members`       | POST     | `tenant.configure`    |
| `/identity/admin/groups/{id}/members/{sub}` | DELETE   | `tenant.configure`    |
| `/identity/me`                              | GET      | `assessment.read`     |
| `/identity/me`                              | PATCH    | `assessment.read`     |
| `/identity/me/devices`                      | GET      | `assessment.read`     |
| `/identity/me/devices/{id}`                 | DELETE   | `assessment.read`     |
| `/identity/me/timeline`                     | GET      | `assessment.read`     |
| `/identity/groups`                          | GET      | `governance.read`     |
| `/identity/groups/{id}`                     | GET      | `governance.read`     |
| `/identity/groups/{id}/members`             | GET      | `governance.read`     |

## Tenant Isolation

Every request extracts `actor.tenant_id` from the auth context. If `tenant_id` is None,
the request is rejected with HTTP 403. All service calls pass `tenant_id` explicitly —
repositories use `(tenant_id, id)` composite keys to prevent cross-tenant data access.

## Pagination

List endpoints accept:
- `limit` (int, 1–500, default 50)
- `offset` (int, ≥0, default 0)

Response includes `total` count for all list endpoints.

## Invitation Acceptance (Canonical P-113.8 Endpoint)

`POST /identity/invitations/{token}/accept` is the only workforce invitation
acceptance authority. It requires the internal admin gateway and verified
named-user identity headers; the actor is resolved canonically from that
identity and the invitation email. Caller-supplied actor attribution is not
accepted.

Error codes include `IDENTITY_UNVERIFIED`, `INVITATION_EMAIL_MISMATCH`, and
replay/expired invitation failures.
- `404 Not Found` — invalid token
