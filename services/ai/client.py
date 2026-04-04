from typing import Any

try:
    from openai import OpenAI  # type: ignore
except Exception:  # pragma: no cover
    OpenAI = Any  # fallback for typing
