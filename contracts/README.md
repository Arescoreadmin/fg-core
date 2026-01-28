# FrostGate Contracts

This folder contains shared API contracts and schemas used across FrostGate services.

## Structure

```
contracts/
  admin/           # Admin Gateway API schemas
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

JSON schema files are auto-generated from Pydantic models. Use `make contracts-gen` to regenerate.

## Adding New Contracts

1. Define Pydantic models in the appropriate `schemas.py` file
2. Export models in `__init__.py`
3. Run `make contracts-gen` to generate JSON schemas
4. Commit both Python files and generated JSON schemas
