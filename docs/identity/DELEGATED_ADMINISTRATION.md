# Delegated Administration

## Hierarchy

```
PLATFORM_ADMIN
    └── TENANT_ADMIN
            └── REGIONAL_ADMIN
                    └── BUSINESS_UNIT_ADMIN
                            └── DEPARTMENT_ADMIN
                                    └── PROJECT_ADMIN
                                            └── ENGAGEMENT_ADMIN
```

## Delegation Rules

1. **Scope inheritance**: A delegated admin may only operate within their own scope
   (tenant, region, business unit, department, project, or engagement).
2. **Escalation prevention**: An admin at level N cannot grant level N or higher to another
   subject. Only higher-level admins can grant their own level.
3. **Tenant boundary**: `TENANT_ADMIN` is the highest level a tenant-scoped admin can hold.
   Only `PLATFORM_ADMIN` can promote to `TENANT_ADMIN`.
4. **Scope validation**: The `DelegatedAdminScope` on a grant must be a sub-scope of the
   granting admin's own scope.

## Permissions Used by Administration

| Permission        | Scope                                       |
|-------------------|---------------------------------------------|
| `user.invite`     | Invite new users to the tenant              |
| `tenant.configure`| Modify lifecycle states, groups, devices    |
| `governance.read` | Read user lists, audit, timeline, groups    |
| `platform.admin`  | Platform-wide operations (cross-tenant)     |

## Current Implementation

Delegated administration records are stored in `DelegatedAdminRecord` (see
`api/identity_governance/models.py`) and managed by `DelegatedAdminAuthority`
(see `api/identity_governance/delegated_admin.py`).

The `IdentityAdministrationService` (PR-02) uses the existing permission system
and does not implement a new delegation layer. Future work (PR-03+) will integrate
`DelegatedAdminAuthority` for fine-grained scope control within the administration
routes.
