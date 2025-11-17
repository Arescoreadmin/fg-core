"""FastAPI entrypoint for the Frostgate backend."""

from fastapi import FastAPI

from .api import routes

app = FastAPI(title="Frostgate Core", version="0.1.0")
app.include_router(routes.router)


@app.get("/", tags=["Meta"], summary="Service metadata")
async def root() -> dict[str, str]:
    """Simple welcome payload for quick smoke tests."""
    return {"message": "Frostgate backend is online"}
