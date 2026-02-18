from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class EvidenceAnchorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_path: str
    external_anchor_ref: str | None = None
    immutable_retention: bool = True
