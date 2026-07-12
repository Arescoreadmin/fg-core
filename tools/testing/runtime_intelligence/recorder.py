"""Write runtime artifacts to disk."""

from __future__ import annotations

from pathlib import Path

from .models import RuntimeResult
from .serializer import to_json


def record_gate_result(result: RuntimeResult, artifact_dir: Path) -> Path:
    """Write the runtime result JSON artifact. Returns the written path."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    gate_slug = result.meta.gate.replace("/", "-")
    out_path = artifact_dir / f"{gate_slug}.json"
    out_path.write_text(to_json(result) + "\n", encoding="utf-8")
    return out_path
