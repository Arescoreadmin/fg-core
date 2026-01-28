# FrostGate Contracts

This folder contains shared API contracts and schemas used across FrostGate services.

## Structure

```
contracts/
  admin/           # Admin Gateway API schemas
    openapi.json   # Admin Gateway OpenAPI schema
    health.json    # Health check response schema
    version.json   # Version response schema
    audit.json     # Audit log entry schema
    __init__.py    # Python exports
    schemas.py     # Pydantic models
```

## Usage

### Python (Pydantic)

```python
from contracts.admin.schemas import HealthResponse, VersionResponse, AuditLogEntry
```

### JSON Schema

OpenAPI and JSON schema files are auto-generated. Use `make contracts-gen` to regenerate.

## Adding New Contracts

1. Define Pydantic models in the appropriate `schemas.py` file
2. Export models in `__init__.py`
3. Run `make contracts-gen` to generate OpenAPI and JSON schemas
4. Commit both Python files and generated artifacts
