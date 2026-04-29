from __future__ import annotations

import logging
import os

from services.ai.providers.base import (
    AI_SIMULATED_PROVIDER_DISABLED,
    ProviderCallError,
    ProviderRequest,
    ProviderResponse,
)
from services.ai_plane_extension.orchestration import deterministic_simulated_response

log = logging.getLogger("frostgate.ai.simulated")

SIMULATED_MODEL = "SIMULATED_V1"


def _simulated_allowed() -> bool:
    fg_env = (os.getenv("FG_ENV") or "").strip().lower()
    prod_like = fg_env in {"prod", "production", "staging"}
    flag = (
        (os.getenv("FG_AI_ENABLE_SIMULATED") or ("0" if prod_like else "1"))
        .strip()
        .lower()
    )
    return flag in {"1", "true", "yes", "on"}


class SimulatedProvider:
    def call(self, req: ProviderRequest) -> ProviderResponse:
        if not _simulated_allowed():
            raise ProviderCallError(
                AI_SIMULATED_PROVIDER_DISABLED,
                "Simulated provider is disabled in this environment",
            )
        text = deterministic_simulated_response(req.prompt)
        return ProviderResponse(
            provider_id="simulated",
            text=text,
            model=SIMULATED_MODEL,
        )
