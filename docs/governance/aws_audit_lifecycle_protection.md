# AWS Audit Lifecycle Protection

**Scope:** `infra/aws_audit.tf` — Customer-Zero Vault audit boundary.
**Status:** All 6 preserved AWS audit resources (4 WRITER + 2 READER) carry
`lifecycle { prevent_destroy = true }` as of
CUSTOMER-ZERO-RUN3-AWS-AUDIT-LIFECYCLE-001.
**Canonical source of truth:** `customer_one/ceremony_state.yaml` →
`cost_containment.preserved_aws_resources`.

## Protected resources

| Terraform address | Category | Role in audit boundary |
| --- | --- | --- |
| `aws_cloudwatch_log_group.vault_audit` | WRITER | Destination log group for HCP Vault audit events. Loss destroys historical ceremony evidence. |
| `aws_iam_user.vault_audit` | WRITER | HCP Vault streaming identity (`frostgate-hcp-vault-audit`). Access key is created out-of-band and lives only in HCP UI. |
| `aws_iam_policy.vault_audit` | WRITER | Minimal write permissions scoped to the audit log group (plus the AWS-mandated unscoped `DescribeLogGroups`). |
| `aws_iam_user_policy_attachment.vault_audit` | WRITER | Binding that grants the WRITER user its policy. Destruction without replacement breaks audit streaming. |
| `aws_iam_role.vault_audit_reader` | READER | MFA-gated, operator-only role (`FrostGateVaultAuditReader`) used for independent historical verification. |
| `aws_iam_role_policy_attachment.vault_audit_reader` | READER | Binding that grants the READER role its read-only policy. |

`aws_iam_policy.vault_audit_reader` is deliberately **not** on the preserved
list — it is a policy document that can be regenerated from Terraform without
losing data if the role attachment is intact. Only the role itself and its
attachment are considered load-bearing.

## What `prevent_destroy` protects

- **Any `terraform destroy`** (whole-config or `-target=...`) targeting a
  protected address errors out before the AWS API is called.
- **Any `terraform plan`/`apply`** whose plan contains a destroy action on a
  protected address errors out before applying. Resource replacement
  (destroy-and-recreate caused by name/path change) is also blocked — the
  operator must either edit the lifecycle block or import a replacement
  explicitly.

## What `prevent_destroy` does **not** protect against

- Someone editing `infra/aws_audit.tf` to remove the lifecycle block, then
  running `terraform apply`. The static gate
  (`tools/ci/check_aws_audit_lifecycle.py`, wired into `make fg-fast`) catches
  this in CI before merge.
- Destruction performed directly in the AWS Console or via `aws` CLI (bypassing
  Terraform). AWS-side protection would require Organizations SCPs or an
  explicit resource policy denying `iam:DeleteUser`,
  `iam:DeletePolicy`, `iam:DetachUserPolicy`, and `logs:DeleteLogGroup` on
  these ARNs. That control is out of scope for this governance doc.
- State-file surgery (`terraform state rm` followed by manual deletion).
  Terraform forgets the resource; `prevent_destroy` cannot block what
  Terraform no longer manages. The static gate's inventory check surfaces
  this only indirectly, by detecting that the resource block is missing from
  the config.
- Account-level or region-level deletion events (account closure, region
  deprecation).

## Verifying protection offline

Any of the following must pass without AWS access:

```bash
# Direct static gate — single command:
python tools/ci/check_aws_audit_lifecycle.py

# Via Make target (also run as part of fg-fast):
make aws-audit-lifecycle-check

# Via the fg-fast lane:
make fg-fast
```

Successful output lists all 6 resources with
`lifecycle { prevent_destroy = true }` and prints `PASS`. Exit code 0.

For a stronger confirmation, run the regression suite:

```bash
pytest tests/test_cz_run3_aws_audit_lifecycle_001.py -v
```

16 tests cover positive invariants (7) and adversarial tampering of a copy of
the Terraform (9 — removed lifecycle, flipped to false, deleted block,
renamed resource, duplicate lifecycle, empty file, malformed HCL, CLI exit
codes).

## Legitimate emergency retirement

If a protected resource genuinely must be retired, the only authorized path is:

1. Document the retirement in a REPAIR-class PR (`docs/governance/` entry +
   `docs/ai/PR_FIX_LOG.md` + `docs/SOC_EXECUTION_GATES_2026-02-15.md`).
2. Remove the address from the `PROTECTED_ADDRESSES` tuple in
   `tools/ci/check_aws_audit_lifecycle.py` **and** from
   `cost_containment.preserved_aws_resources` in
   `customer_one/ceremony_state.yaml`. Test P-007 (set equality between the
   gate inventory and the ceremony state) enforces that these two changes
   stay in lockstep.
3. Remove the `lifecycle { prevent_destroy = true }` block from the resource.
4. Only then run `terraform apply`.

Independent governance review is required before step 4. The three-way
coupling (Terraform + static gate inventory + ceremony state) is intentional:
no single file edit can quietly weaken the audit boundary without the review
machinery noticing.
