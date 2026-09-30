"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    artifacts,
    chat,
    clients,
    dast,
    export,
    findings,
    mcp,
    projects,
    scans,
    settings as settings_api,
    stream,
)
from app.config import settings
from app.db import init_models

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev convenience: create tables. Prod runs Alembic migrations instead.
    await init_models()
    yield


app = FastAPI(
    title="AI Vuln Code Hunter",
    version="0.1.0",
    description="Agentic AI code-security review (Azure AI Foundry).",
    lifespan=lifespan,
)

@app.middleware("http")
async def _json_errors(request: Request, call_next):
    """Turn unhandled exceptions into a JSON 500 *inside* the CORS middleware
    (registered before it, so CORS wraps it). Otherwise Starlette's outermost
    error handler replies without CORS headers and the browser only shows an
    opaque "NetworkError" instead of the actual error."""
    try:
        return await call_next(request)
    except Exception as exc:  # noqa: BLE001
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500,
                            content={"detail": f"{type(exc).__name__}: {exc}"[:500]})


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.environment == "dev" else [settings.api_base_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (clients, projects, artifacts, scans, findings, export, mcp, chat,
               stream, settings_api, dast):
    app.include_router(module.router, prefix="/api")


@app.get("/api/health", tags=["meta"])
async def health():
    return {
        "status": "ok",
        "environment": settings.environment,
        "auth_disabled": settings.auth_disabled,
        "foundry_mock": settings.foundry_mock,
    }


@app.get("/", tags=["meta"])
async def root():
    return {"service": "ai-vuln-code-hunter", "docs": "/docs"}
