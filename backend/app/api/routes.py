"""HTTP routes exposed by the Frostgate backend."""

from fastapi import APIRouter

from ..schemas import IntelReport, Mission
from ..services.intel import list_reports
from ..services.missions import list_missions

router = APIRouter()


@router.get("/health", summary="Readiness probe", tags=["Health"])
async def health() -> dict[str, str]:
    """Return a simple payload so orchestrators know the service is running."""
    return {"status": "ok"}


@router.get(
    "/missions",
    summary="Preview planned operations",
    tags=["Missions"],
    response_model=list[Mission],
)
async def missions() -> list[Mission]:
    """Expose a static list of missions so the product team can iterate on the UX."""
    return list_missions()


@router.get(
    "/intel",
    summary="Surface intel briefings",
    tags=["Intel"],
    response_model=list[IntelReport],
)
async def intel() -> list[IntelReport]:
    """Provide a curated set of intel reports for operators."""

    return list_reports()
