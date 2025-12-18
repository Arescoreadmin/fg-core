from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from api.db import init_db
from api.defend import router as defend_router
from api.decisions import router as decisions_router
from api.ingest import router as ingest_router

logger = logging.getLogger("frostgate")

logging.basicConfig(
    level=os.getenv("FG_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title="Frostgate Core",
    version=os.getenv("FG_VERSION", "0.2.0"),
    description="Frostgate Core – deterministic defense + telemetry ingestion.",
    openapi_tags=[
        {"name": "health", "description": "Service health endpoints"},
        {"name": "meta", "description": "Service metadata"},
        {"name": "ingest", "description": "Agent-facing telemetry intake"},
        {"name": "defend", "description": "Decision engine (admin scope)"},
        {"name": "decisions", "description": "Decision query API"},
    ],
)

Instrumentator().instrument(app).expose(app)

# Router order is intentional:
#  - ingest: write-heavy, agent-facing
#  - defend: decision engine
#  - decisions: read-only queries
app.include_router(ingest_router)
app.include_router(defend_router)
app.include_router(decisions_router)

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Frostgate Core DB initialized")

@app.get("/health/live", tags=["health"])
async def health_live() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/health/ready", tags=["health"])
async def health_ready() -> dict[str, str]:
    # If init_db succeeded, we're "ready" for MVP.
    # Later: add DB ping, redis ping, queue status, etc.
    return {"status": "ready"}

@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {"service": "frostgate-core", "status": "ok", "version": app.version}
