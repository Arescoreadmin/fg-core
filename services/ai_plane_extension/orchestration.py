from __future__ import annotations

import hashlib


def deterministic_simulated_response(query: str) -> str:
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
    return f"SIMULATED_RESPONSE:{digest[:16]}"
