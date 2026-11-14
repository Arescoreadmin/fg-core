# MSP-002 operator guide

This guide covers the console workflows for the managed service provider (MSP) and for the customer. It also lists the steps FrostGate operations must complete before first use.

## Before first use (FrostGate operations)

1. **Apply the migration.** Migration 0206 must be applied in the target environment.
2. **Check the console configuration.** The console must have `FG_INTERNAL_GATEWAY_SECRET` and `FG_GATEWAY_DELEGATION_SECRET_CURRENT` configured. Both are already required for existing administration.
3. **Provision the MSP.** Use the normal tenant provisioning flow, then onboard the MSP's administrators as bound `tenant_admin` users of that tenant.
4. **Designate the tenant as an MSP.** Through the internal admin gateway (not the console):

   ```
   PUT /admin/msp/organizations/{msp_tenant_id}  {"status": "active"}
   ```

5. **Assign the entitlement.** Give the MSP tenant the `msp.multi_tenant` entitlement bundle.
6. **Emergency stop.** `PUT /admin/msp/organizations/{id} {"status": "suspended"}` denies every customer for that MSP on the next request.

## MSP workflow (`/msp`)

**Open the page.** Sign in as an MSP administrator, then go to **Organization → MSP portfolio**.

**Request access to a customer.**

1. Enter the customer's organization ID. The customer's administrator copies it from their **Managed service partners** page.
2. Choose the read-only capabilities you need.
3. Send the request. It shows as *Awaiting customer approval*. You have no access until the customer approves.

**Work with authorized customers.** The table lists only customers that currently allow you access. For each customer it shows:

- the capabilities that customer delegated;
- assessment and findings summaries, where delegated;
- when access ends.

These summary messages can appear:

| Message | Meaning |
|---|---|
| *Not delegated by the customer* | The customer did not approve that capability. |
| *No data recorded yet* | Nothing exists yet. This is not a zero score. |
| *Temporarily unavailable* | The read failed this time. Retry later. |

**Open a customer.** **Open** re-checks your access, records the selection in both audit chains, and shows the next step. It does not grant anything new.

**Inaccessible customers.** These appear under *Your requests and ended relationships*, with the reason: pending, suspended by the customer, expired or revoked. No other customer details are shown.

**End a relationship.** Use **End relationship**, or **Withdraw request** while it is still pending. You cannot restore it afterwards; you would need to send a new request.

## Customer workflow (`/partners`)

**Open the page.** Sign in as a customer administrator, then go to **Organization → Managed service partners**.

**Review a request.** Each card shows the requesting MSP and the capabilities it asked for.

**Approve.**

1. Select **Review and approve**.
2. Approve fewer capabilities if you wish.
3. Choose how long access lasts, from 1 to 366 days. Access starts immediately.
4. Confirm.

**Change access later.** Each of these requires confirmation and applies to the MSP's very next request:

| Action | Effect |
|---|---|
| **Suspend** | Pauses access. |
| **Resume** | Restores it within the original approval period. |
| **Revoke** | Ends it permanently. |

**View history.** **View history** lists, from your own audit chain, every step on that relationship: requested, approved, opened, viewed summaries, suspended and revoked. It also shows whether the chain verified intact.

Revocation never changes your records, evidence or audit history.

## Troubleshooting

| Message | Cause |
|---|---|
| *Your organization is not set up as an active managed service provider* | The MSP is not designated or has been suspended, or the signed-in user is not a bound member. |
| *Only organization administrators can manage MSP relationships* | The console's MSP surfaces require the `tenant_admin` role. |
| *This relationship changed since you loaded it* | Another administrator acted first. The page reloads; review it and retry. |
| *Your session has expired* | Sign in again. Nothing was changed. |

## Synthetic demonstration

`tests/security/test_msp_002_console_transport.py::test_first_client_demonstration` runs all 11 acceptance steps through the console's real transport, using synthetic tenants:

```
.venv/bin/python -m pytest -q tests/security/test_msp_002_console_transport.py -k demonstration
```

A passing demonstration is not production readiness. See `MSP_FIRST_CLIENT_READINESS.md`.
