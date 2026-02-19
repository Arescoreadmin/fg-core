from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class TenantControlStateUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    status: str
    note: str | None = None
