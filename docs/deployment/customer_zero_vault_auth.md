# Customer-Zero Vault authentication

The Customer-Zero trust adapter targets HCP Vault Dedicated Transit with Ed25519 keys. Runtime authentication is role-specific and short-lived. The application-side implementation supports bounded AppRole sessions with lease expiry, renewal, and re-authentication; an approved Railway workload JWT/OIDC assertion is not assumed by this repository and must be established before adding a JWT adapter.

Three runtime roles are mapped independently to Vault AppRole role IDs and Transit key IDs: `customer-zero-identity`, `customer-zero-acceptance`, and `customer-zero-approval`. Role IDs and key IDs must be distinct. AppRole SecretIDs are supplied only by the approved runtime secret mechanism and are never logged, persisted, or included in exceptions.

Operational mode requires an HTTPS Vault address, certificate verification, bounded HTTP timeouts, disabled redirects, validated namespace/key identifiers, and no static-token fallback. `FG_CUSTOMER_ZERO_VAULT_AUTH_MODE=static_token` is explicitly limited to local/test/development compatibility; production requires `approle` and role-specific configuration. The adapter never handles signing private keys.

External provisioning remains required: HCP Vault, three non-exportable Transit Ed25519 keys, least-privilege policies/auth roles, runtime authentication, public trust-anchor enrollment, rotation/history evidence, and independent operational verification. This document does not claim that provisioning occurred.
