# FrostGate Core – System Contract

This document defines **non-negotiable invariants** for FrostGate Core.
Anything that violates this contract is a bug, not a preference.

If tests pass but this contract is broken, the system is broken.

---

## 1. Application Construction

### 1.1 build_app is the Source of Truth

- All FastAPI applications MUST be created via:

```python
build_app(auth_enabled: bool)
