# Console Tenant Experience Wireframes - 2026-08-06

Text wireframes only. These are planning artifacts, not implementation specs.

## Tenant detail page

```text
All clients / Odin Financial Group

Odin Financial Group
Tenant ID: odin-financial-group          Status: Active   Identity: Managed   Health: OK

[ Overview ] [ Console users ] [ Portal access ] [ Identity governance ] [ Audit history ]

┌──────────────────────────────────────────────────────────────────────────────┐
│ Selected tab content                                                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

Narrow layout:

```text
< All clients
Odin Financial Group
Tenant ID: odin-financial-group
Status: Active

[ Overview        v ]
```

## Console user tab

```text
Console users                                             [ Invite console user ]
Staff with direct Console access for Odin Financial Group.

┌──────────────┬──────────────┬──────────┬────────────┬────────────┬──────────┐
│ Email        │ Name         │ Role     │ Status     │ Last active│ Actions  │
├──────────────┼──────────────┼──────────┼────────────┼────────────┼──────────┤
│ j@odin.com   │ Jane Smith   │ Admin    │ Pending    │ -          │ Revoke   │
│ a@odin.com   │ Alex Kim     │ Auditor  │ Active     │ Today      │ Disable  │
└──────────────┴──────────────┴──────────┴────────────┴────────────┴──────────┘

Evidence
Last invitation event: console_invitation.sent
Request ID: req_...
```

Empty state:

```text
Console users

No console users have been invited for Odin Financial Group.
[ Invite console user ]
```

## Invitation modal

```text
┌─────────────────────────────────────────────────────────────┐
│ Invite console user                                         │
│                                                             │
│ Tenant                                                      │
│ Odin Financial Group                                        │
│ Tenant ID: odin-financial-group                             │
│                                                             │
│ Email                                                       │
│ [ user@odin.com                                      ]       │
│                                                             │
│ Display name                                                │
│ [ Jane Smith                                         ]       │
│                                                             │
│ Console role                                                │
│ [ Admin                                             v ]      │
│ Can manage tenant settings, users, and portal access.        │
│                                                             │
│                         [ Cancel ] [ Send invitation ]       │
└─────────────────────────────────────────────────────────────┘
```

Permission denied state:

```text
┌─────────────────────────────────────────────────────────────┐
│ Cannot invite console users                                 │
│ Your account does not have invitation authority for          │
│ Odin Financial Group.                                       │
│                                                             │
│ Required authority: user.invite or admin tenant invitation   │
│ Request ID: req_...                                         │
│                                                             │
│                                      [ Close ]               │
└─────────────────────────────────────────────────────────────┘
```

Success state:

```text
Invitation sent

Jane Smith has been invited to Odin Financial Group.
Status: Pending acceptance
Expires: Aug 9, 2026
Audit event: console_invitation.sent
Request ID: req_...

[ View invitation ] [ Invite another user ]
```

## Portal access tab

```text
Portal access                                           [ Create portal access ]
Client-facing portal access for Odin Financial Group.

┌──────────────┬────────────────────┬────────────┬──────────┬────────────┬─────┐
│ Recipient    │ Engagement         │ View       │ Status   │ Expires    │ ... │
├──────────────┼────────────────────┼────────────┼──────────┼────────────┼─────┤
│ cfo@odin.com │ 2026 AI Assessment │ Executive  │ Pending  │ Sep 5      │ ... │
│ it@odin.com  │ 2026 AI Assessment │ Technical  │ Active   │ Sep 5      │ ... │
└──────────────┴────────────────────┴────────────┴──────────┴────────────┴─────┘
```

Empty state:

```text
Portal access

No portal access has been issued for Odin Financial Group.
Create access after selecting a tenant-owned engagement.

[ Create portal access ]
```

## Portal grant modal

Preferred named-user invitation shape:

```text
┌─────────────────────────────────────────────────────────────┐
│ Create portal access                                        │
│                                                             │
│ Tenant                                                      │
│ Odin Financial Group                                        │
│ Tenant ID: odin-financial-group                             │
│                                                             │
│ Engagement                                                  │
│ [ 2026 AI Governance Assessment                     v ]      │
│ Status: QA approved   Engagement ID: eng_...                 │
│                                                             │
│ Portal view                                                 │
│ [ Executive                                         v ]      │
│ Summary posture and board-ready evidence.                   │
│                                                             │
│ Access duration                                             │
│ [ 30 days                                           v ]      │
│                                                             │
│ Recipient email                                             │
│ [ cfo@odin.com                                      ]        │
│                                                             │
│ Recipient name                                              │
│ [ Morgan Lee                                       ]         │
│                                                             │
│                         [ Cancel ] [ Send invitation ]       │
└─────────────────────────────────────────────────────────────┘
```

Legacy grant compatibility detail, if raw grant still exists temporarily:

```text
Advanced details
Access type: Legacy grant credential
Raw secret will be shown once and must not be logged.
```

## Invitation lifecycle table

```text
Invitation lifecycle

┌──────────────┬────────────┬────────────┬────────────┬────────────┬──────────┐
│ Recipient    │ Type       │ Status     │ Sent       │ Expires    │ Actions  │
├──────────────┼────────────┼────────────┼────────────┼────────────┼──────────┤
│ jane@odin... │ Console    │ Pending    │ Today      │ Aug 9      │ Resend   │
│ cfo@odin...  │ Portal     │ Accepted   │ Yesterday  │ Sep 5      │ Revoke   │
│ it@odin...   │ Portal     │ Failed     │ Today      │ Sep 5      │ Retry    │
└──────────────┴────────────┴────────────┴────────────┴────────────┴──────────┘
```

## Error states

Tenant mismatch:

```text
Tenant context mismatch

This action was blocked because the request did not match Odin Financial Group.
No invitation or access grant was created.
Request ID: req_...
```

Engagement mismatch:

```text
Engagement unavailable

The selected engagement is not available for Odin Financial Group.
Choose an engagement from the list and try again.
Request ID: req_...
```

Email delivery failure:

```text
Invitation created, email not sent

The invitation is pending, but email delivery failed.
Delivery error: resend_unavailable
Request ID: req_...

[ Retry email ] [ Copy invitation link ]
```

## Mobile/narrow layout considerations

```text
Odin Financial Group
Tenant ID: odin-financial-group

[ Console users v ]

Invite button full width.
Tables become stacked rows:

Email
jane@odin.com
Role
Admin
Status
Pending
[ Revoke ]
```

Rules:

- Tenant context remains visible above every action.
- Long IDs wrap in secondary text and never force horizontal page scroll.
- Modals become full-width sheets on narrow screens.
- Primary action remains last in tab order.
- Permission-denied and success states include request ID.
