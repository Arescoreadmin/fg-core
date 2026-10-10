# Customer-Zero Run-3 Audit-First Smoke Test Contract

**Document ID:** SMOKE-TEST-RUN3-001
**Audit:** CZ-RUN3-FAILURE-PREVENTION-001
**Canonical Source SHA:** ec8684df4699be43b40d1edc9a79b58fd23e3637
**Date:** 2026-10-09
**Classification:** OFFLINE_PREPARATION — defines live ceremony steps, executed at ceremony time

---

## Purpose

This smoke test contract defines the exact steps an operator MUST complete before any
substantive ceremony work begins. The audit-first requirement is drawn from the historical
failure record: in Runs 1 and 2, the CloudWatch audit proof was not independently verified
before signing proofs were attempted. This contract prevents that failure mode from recurring.

**Invariant:** No signing proof (A-family, B-family, C-family, D-family, E-family, F-family,
H-family) may begin until the audit smoke test passes.

---

## Preconditions

All of the following must be true before the smoke test begins:

1. Human cost authorization is obtained and on record.
2. HCP Vault Dedicated cluster is provisioned and ACTIVE.
3. Vault Transit engine is configured (three keys created).
4. AppRole authentication is configured (three roles created).
5. FrostGate runtime can authenticate via AppRole (connectivity proven).
6. IAM access key for `frostgate-hcp-vault-audit` user is created (out-of-band, not in Terraform state).
7. HCP Vault cluster audit logging is configured (HCP UI: Cluster → Observability → Audit Logging → destination: CloudWatch log group name from Terraform output).

---

## Smoke Test Steps

### Step 1: Confirm Audit Infrastructure Is Active

```bash
aws sts get-caller-identity --profile frostgate-operator
# Expected: operator identity, not vault_audit user
```

Verify all four preserved AWS resources are ACTIVE:
- `aws_cloudwatch_log_group.vault_audit` — check AWS CloudWatch console
- `aws_iam_user.vault_audit` — check IAM console
- `aws_iam_policy.vault_audit` — check IAM console
- `aws_iam_user_policy_attachment.vault_audit` — attached to user

**Failure condition:** Any resource absent or inactive → STOP, investigate, do not proceed.

### Step 2: Execute a Vault Operation to Generate Audit Event

Execute a minimal, non-destructive Vault operation to generate an audit event.
The safest is a key read (does not sign or modify):

```bash
# With the bootstrap admin token (pre-ceremony):
vault token lookup
# Or: vault read transit/keys/customer-zero-identity
```

Record the exact UTC timestamp of the operation.

**Failure condition:** Vault operation fails → STOP, diagnose Vault connectivity.

### Step 3: Verify Audit Event Arrived in CloudWatch

Within 60 seconds of the Vault operation:

1. Assume the reader role (MFA required):
   ```bash
   aws sts assume-role \
     --role-arn arn:aws:iam::ACCOUNT_ID:role/FrostGateVaultAuditReader \
     --role-session-name smoke-test-$(date +%s) \
     --serial-number arn:aws:iam::ACCOUNT_ID:mfa/DEVICE \
     --token-code MFA_CODE
   ```

2. Query CloudWatch for events after the recorded timestamp:
   ```bash
   aws logs filter-log-events \
     --log-group-name CLOUDWATCH_LOG_GROUP_NAME \
     --start-time EPOCH_MILLISECONDS \
     --query 'events[*].message' \
     --output text | head -5
   ```

**Pass condition:** At least one audit event appears in CloudWatch with a timestamp matching
or after the Vault operation timestamp.

**Failure condition:** No events appear within 2 minutes → ABORT-POST-003 (controlled teardown).
Do NOT proceed to signing proofs. There is no partial-audit trust proof.

### Step 4: Record Smoke Test Evidence

Record the following in the ceremony evidence file:
- Vault operation timestamp (UTC)
- CloudWatch event count at smoke test time
- CloudWatch log group name (must match Terraform output `cloudwatch_log_group_name`)
- Reader role ARN used
- Smoke test pass/fail result
- Operator identity performing the test

### Step 5: Sign Off Before Proceeding

The smoke test must be explicitly signed off by the operator before any signing proofs begin:

```
AUDIT_SMOKE_TEST: PASS
Timestamp: <UTC>
CloudWatch events confirmed: <count>
Log group: <name>
Operator: Jason Cosat
Proceeding to: A-IDENTITY-SIGN
```

**If the smoke test result is anything other than PASS:** Execute teardown immediately.
Do not attempt to debug the audit integration with paid infrastructure running.

---

## Checkpoint Q (Post-Proof Verification)

After all signing proofs complete, before trust determination:

Execute Checkpoint Q as defined in the operator preflight runbook:
1. Repeat Steps 3–4 above.
2. Verify that audit events from all ceremony signing operations appear in CloudWatch.
3. Capture evidence: log stream names, event count, sample event bodies.
4. Record Checkpoint Q result.

**Failure condition:** Audit events absent for any signing operation → trust determination
is INCOMPLETE. Record the gap explicitly. Do not claim full trust proof.

---

## Abort Conditions

| Condition | Abort code | Action |
|-----------|-----------|--------|
| Step 1: AWS resource absent | ABORT-CER-001 | Stop; investigate; do not provision Vault |
| Step 2: Vault operation fails | ABORT-CER-001 | Stop; diagnose; do not proceed to smoke test |
| Step 3: CloudWatch events absent after 2 minutes | ABORT-POST-003 | Immediate controlled teardown |
| Checkpoint Q: Events absent for any proof | (Record gap, do not declare full trust) | Document incomplete proof; proceed to teardown |

---

## Evidence Capture Template

```json
{
  "smoke_test_id": "SMOKE-TEST-RUN3-<timestamp>",
  "test_date": "<ISO-8601>",
  "operator": "Jason Cosat",
  "canonical_sha": "ec8684df4699be43b40d1edc9a79b58fd23e3637",
  "vault_operation_timestamp": "<ISO-8601>",
  "cloudwatch_log_group": "<log_group_name>",
  "cloudwatch_events_confirmed": <count>,
  "reader_role_arn": "<arn>",
  "smoke_test_result": "PASS|FAIL",
  "checkpoint_q_result": "PASS|FAIL|INCOMPLETE",
  "checkpoint_q_event_count": <count>,
  "notes": ""
}
```

---

## Why Audit-First Matters

Historical record from `ceremony_state.yaml`:
```
proven_during_ceremonies:
  - "AWS CloudWatch audit log group was confirmed to receive Vault audit events"

not_proven_during_ceremonies:
  - "Report/provenance integrity: ..."  (now REPAIRED)
  - "Verifier contract: ..."            (now REPAIRED)
  - "Customer-Zero acceptance: all required proof elements are not yet present simultaneously"
```

The CloudWatch confirmation in Runs 1 and 2 was incomplete — not independently verified as
a discrete step before signing proofs began. This contract ensures that verification is an
explicit blocker, not an afterthought.
