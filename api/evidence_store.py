from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol


class EvidenceStoreAccessError(PermissionError):
    pass


def _require_scope(scopes: set[str], required_scope: str = "audit:evidence:read") -> None:
    if required_scope not in scopes:
        raise EvidenceStoreAccessError("AUDIT_EVIDENCE_FORBIDDEN")


class EvidenceStore(Protocol):
    def put_atomic(self, *, tenant_id: str, export_id: str, content: bytes) -> tuple[str, int]: ...

    def get_bytes(self, *, tenant_id: str, export_id: str, scopes: set[str]) -> bytes: ...

    def list_export_ids(self, *, tenant_id: str, job_id: str, scopes: set[str]) -> list[str]: ...


class LocalFileEvidenceStore:
    def __init__(self, root: Path):
        self.root = root

    def put_atomic(self, *, tenant_id: str, export_id: str, content: bytes) -> tuple[str, int]:
        directory = self.root / tenant_id
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{export_id}.json"
        with tempfile.NamedTemporaryFile("wb", dir=directory, delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, target)
        return f"file://{target}", len(content)

    def get_bytes(self, *, tenant_id: str, export_id: str, scopes: set[str]) -> bytes:
        _require_scope(scopes)
        p = (self.root / tenant_id / f"{export_id}.json").resolve()
        tenant_root = (self.root / tenant_id).resolve()
        if not str(p).startswith(str(tenant_root)):
            raise EvidenceStoreAccessError("AUDIT_EVIDENCE_FORBIDDEN")
        return p.read_bytes()

    def list_export_ids(self, *, tenant_id: str, job_id: str, scopes: set[str]) -> list[str]:
        _require_scope(scopes)
        if not str(job_id).strip():
            raise EvidenceStoreAccessError("AUDIT_EVIDENCE_JOB_FILTER_REQUIRED")
        directory = (self.root / tenant_id)
        if not directory.exists():
            return []
        prefix = f"{job_id}-"
        return sorted([p.stem for p in directory.glob(f"{prefix}*.json")])
