from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EvidenceDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_path: str
    generator_script: str


class PlaneDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plane_id: str
    route_prefixes: list[str] = Field(default_factory=list)
    mount_flag: str
    required_make_targets: list[str] = Field(default_factory=list)
    evidence: list[EvidenceDef] = Field(default_factory=list)
    required_route_invariants: list[str] = Field(default_factory=list)
