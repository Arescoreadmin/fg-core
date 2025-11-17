"""HTTP routes exposed by the Frostgate backend."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Readiness probe", tags=["Health"])
async def health() -> dict[str, str]:
    """Return a simple payload so orchestrators know the service is running."""
    return {"status": "ok"}
