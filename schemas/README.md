# Schema Registry (Single Source of Truth)

This directory is the canonical registry for API, event, and artifact schemas.
Every schema must declare a version and be listed in `schemas/registry.json`.

## Versioning Rules

- **API (OpenAPI)**: `info.version` must be semver (e.g., `1.0.0`).
- **Events**: must declare a `version` property with an enum that is semver.
- **Artifacts**: must declare a `schema_version` property with an enum that is semver.

Any schema file outside the registry is treated as drift and fails CI.
