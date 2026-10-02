# frostgate-infra

Infrastructure-as-code authority for FrostGate production infrastructure.

## Authorized scope

This repository contains exclusively the infrastructure required for:

- HCP project configuration (`frostgate-production`)
- HCP Vault Dedicated cluster (`frostgate-customer-zero`, Standard/Small, AWS us-east-1)
- Vault Transit engine and Customer-Zero trust key configuration
- Three Customer-Zero AppRole auth roles and least-privilege policies
- Three Customer-Zero Ed25519 Transit keys
- AWS CloudWatch Vault audit destination
- Dedicated AWS IAM audit-streaming principal (if required by HCP integration)
- HCP Vault Dedicated → CloudWatch audit stream binding
- Remote Terraform state configuration
- Non-secret infrastructure metadata

## Out of scope

This repository must NOT be used for:

- Multi-cloud or generalized networking infrastructure
- Kubernetes or container orchestration
- Generalized secrets management platform
- Generalized IAM or identity platform
- Generalized observability platform
- CI/CD pipeline redesign
- Production application infrastructure
- Customer-One deployment architecture
- Any infrastructure not explicitly listed under authorized scope

## Security boundaries

**Never commit to this repository:**

- Terraform state files (`.tfstate`, `.tfstate.*`)
- Secret-valued `.tfvars` or `.auto.tfvars` files
- Vault tokens, AppRole SecretIDs, or recovery material
- AWS access keys, secret keys, or IAM credentials
- HCP client secrets or service-principal credentials
- Private keys or certificate material
- `.terraform/` provider binaries

The `.gitignore` in this repository enforces these exclusions. Do not override
or bypass `.gitignore` entries for secret-bearing files under any circumstances.

**DO commit:**

- `.terraform.lock.hcl` (provider version pins — verify it contains no sensitive values)
- Non-secret `.tfvars` files (reviewed explicitly before commit)
- Terraform source files (`.tf`) that contain no inline secret values

## Ceremony

**Ceremony:** `customer-zero-trust-2026-10-02-001`

**Work item:** `CUSTOMER-ZERO-TRUST-001`

**Source authority:** `45f9a8370b9cb1a6c354da290ad3b5cd3ef43104` (fg-core main at ceremony-readiness reconciliation)

> **Historical note:** The ceremony identifier `customer-zero-trust-2026-09-23-001` appeared in
> prior working branches and local plan artifacts. It was not used in any production provisioning.
> `customer-zero-trust-2026-10-01-001` was set during Stage 1.5/1.6 readiness work but the ceremony
> was not executed on that date due to operator identity hardening requirements.
> `customer-zero-trust-2026-10-02-001` is the updated canonical identifier.
> Update again if the actual ceremony is executed on a later date.

## Operator identity pre-conditions

**Root MUST NOT be the routine Terraform operator identity.**

Before `terraform apply`, the following pre-conditions must be satisfied:

1. **Root MFA enabled** — AWS root account MFA must be active (currently: NOT ENABLED).
2. **No root access keys** — root programmatic access keys must never exist (currently: ABSENT — correct).
3. **Operator role bootstrapped** — run `scripts/bootstrap-operator-role.sh` once as root to
   create the `FrostGateTerraformOperator` IAM role with a least-privilege permissions policy
   scoped to exactly the 4 AWS resources in this repository.
4. **Non-root `frostgate-terraform` profile** — run `aws login` (browser-based Console auth),
   switch to `FrostGateTerraformOperator` in the Console; `aws login` updates `~/.aws/config`
   `[default]` automatically. No manual config changes needed.
5. **Pre-existing IAM user conflict** — `frostgate-hcp-vault-audit` was manually created in
   the account at path `/` with no tags or policies. It must be **deleted** before
   `terraform apply` runs, as Terraform will attempt to create it at path `/frostgate/vault/`.

See `docs/operator-hardening.md` for the full operator setup procedure.

## Remote state

Terraform state for this repository uses a durable remote backend.
Local state is not the authoritative production state.
See `terraform.tf` for backend configuration.

## Usage

```bash
# After remote state backend is configured and authentication is established:
terraform init
terraform plan
# STOP — do not apply without explicit operator approval
```

## Providers

| Provider | Purpose |
|---|---|
| `hashicorp/hcp` | HCP organization, project, Vault Dedicated cluster |
| `hashicorp/vault` | Vault Transit, policies, AppRole auth |
| `hashicorp/aws` | CloudWatch log group, IAM audit principal |

## Repository governance

This repository follows the FrostGate `CUSTOMER-ZERO-TRUST-001` work item.
Any expansion of scope requires explicit operator authorization referencing
the FrostGate roadmap authority (`customer_one/roadmap_authority.yaml`).
