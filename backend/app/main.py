"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    artifacts,
    chat,
    clients,
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.environment == "dev" else [settings.api_base_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (clients, projects, artifacts, scans, findings, export, mcp, chat, stream, settings_api):
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
