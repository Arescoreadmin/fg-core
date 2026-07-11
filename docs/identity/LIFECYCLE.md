# Identity Lifecycle States & Transitions

## State Diagram (ASCII)

```
                     ┌─────────────────────────────────────────┐
                     │                  CREATED                │
                     └─────────────┬───────────────────────────┘
                                   │ invite_user()
                                   ▼
                     ┌─────────────────────────────────────────┐
                     │                  INVITED                │
                     └──────┬──────────────────┬──────────────┘
                            │ email sent        │ direct accept
                            ▼                   ▼
              ┌─────────────────────┐  ┌─────────────────────────┐
              │   INVITATION_SENT   │  │        ACCEPTED          │
              └──────────┬──────────┘  └──────────────┬──────────┘
                         │ opened                      │
                         ▼                             │
              ┌─────────────────────┐                  │
              │  INVITATION_OPENED  │──────────────────┘
              └──────────┬──────────┘
                         │ accept
                         ▼
                ┌──────────────────────┐
                │       ACCEPTED       │
                └──────────┬───────────┘
                           │ provision
                           ▼
                ┌──────────────────────┐
                │      PROVISIONED     │
                └──────────┬───────────┘
                           │ activate
                           ▼
  ┌──────────┐   ┌──────────────────────┐   ┌──────────────────────┐
  │  LOCKED  │◄──│        ACTIVE        │──►│  PASSWORD_RESET_     │
  └────┬─────┘   └──────────────────────┘   │     PENDING          │
       │                │          │         └──────────────────────┘
       │                │          │
       │                ▼          ▼
       │        ┌─────────────┐  ┌────────────────────────┐
       │        │  SUSPENDED  │  │ MFA_ENROLLMENT_REQUIRED │
       │        └─────────────┘  └────────────────────────┘
       │                │                   │
       │                │                   ▼
       │                │         ┌──────────────────────┐
       │                │         │       VERIFIED        │
       │                │         └──────────────────────┘
       │                │                   │
       └──────────┬─────┘───────────────────┘
                  │ disable
                  ▼
        ┌─────────────────────┐
        │       DISABLED      │
        └──────────┬──────────┘
                   │ archive
                   ▼
        ┌─────────────────────┐
        │       ARCHIVED      │
        └──────────┬──────────┘
                   │ delete
                   ▼
        ┌─────────────────────┐
        │       DELETED       │ (terminal — no outgoing transitions)
        └─────────────────────┘
```

## Transition Table

| From State              | Valid Target States                                             |
|-------------------------|-----------------------------------------------------------------|
| CREATED                 | INVITED, ACTIVE, DISABLED                                      |
| INVITED                 | INVITATION_SENT, ACCEPTED, DISABLED, ARCHIVED                  |
| INVITATION_SENT         | INVITATION_OPENED, INVITED, DISABLED                           |
| INVITATION_OPENED       | ACCEPTED, INVITATION_SENT                                      |
| ACCEPTED                | PROVISIONED, ACTIVE, SUSPENDED, DISABLED                       |
| PROVISIONED             | ACTIVE, MFA_ENROLLMENT_REQUIRED, PASSWORD_RESET_PENDING        |
| ACTIVE                  | PASSWORD_RESET_PENDING, MFA_ENROLLMENT_REQUIRED, SUSPENDED, LOCKED, DISABLED, ARCHIVED |
| PASSWORD_RESET_PENDING  | ACTIVE, VERIFIED, SUSPENDED, DISABLED                          |
| MFA_ENROLLMENT_REQUIRED | ACTIVE, VERIFIED, SUSPENDED, DISABLED                          |
| VERIFIED                | ACTIVE, SUSPENDED, DISABLED                                    |
| SUSPENDED               | ACTIVE, LOCKED, DISABLED, ARCHIVED                             |
| LOCKED                  | ACTIVE, SUSPENDED, DISABLED                                    |
| DISABLED                | ARCHIVED, DELETED                                              |
| ARCHIVED                | DELETED                                                        |
| DELETED                 | (none — terminal state)                                        |

## Rules

1. **All transitions go through `IdentityLifecycleManager.transition()`** — never set state directly.
2. **Only ACTIVE subjects can authenticate** — `can_authenticate()` returns True only for ACTIVE.
3. **DELETED is terminal** — no transitions out of DELETED.
4. **DISABLED can only go to ARCHIVED or DELETED** — cannot be re-activated directly.
5. **reason and actor are required** on every transition for audit trail.

## New States (PR-02)

| State                   | Description                                                   |
|-------------------------|---------------------------------------------------------------|
| INVITATION_SENT         | Email with invitation link has been sent to the user          |
| INVITATION_OPENED       | User has opened/clicked the invitation link                   |
| PROVISIONED             | Account provisioned but not yet fully activated               |
| PASSWORD_RESET_PENDING  | User must reset their password before proceeding              |
| MFA_ENROLLMENT_REQUIRED | User must enroll an MFA method before proceeding              |
| VERIFIED                | User has completed verification (MFA or password reset)       |
| LOCKED                  | Account temporarily locked (e.g., too many failed attempts)   |

## Authentication Requirement

Only subjects in the `ACTIVE` state may authenticate. All other states result in
authentication being denied. This is enforced by `IdentityLifecycleManager.can_authenticate()`.
