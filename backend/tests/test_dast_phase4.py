"""Phase 4: scripted login_form + IDOR object-id harvesting, against an
in-process target with a login route and a collection/list route."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.dast.client import LiveClient
from app.dast.harvest import collection_path, harvest_object_ids, merge_seeds
from app.dast.identity import Identity
from app.dast.login import parse_spec, perform_login
from app.dast.scope import Scope


def _app():
    async def login(r: Request):
        body = await r.json()
        if body.get("password") == "pw-A":
            return JSONResponse({"data": {"token": "TOK-A"}})
        return JSONResponse({"error": "bad creds"}, status_code=401)

    async def cookie_login(r: Request):
        resp = JSONResponse({"ok": True})
        resp.set_cookie("session", "SESS-A")
        return resp

    async def list_users(r: Request):
        # only a valid token sees the list
        if r.headers.get("authorization") != "Bearer TOK-A":
            return JSONResponse({"error": "unauth"}, status_code=401)
        return JSONResponse({"users": [{"id": 101}, {"id": 102}, {"id": 103}]})

    return Starlette(routes=[
        Route("/api/login", login, methods=["POST"]),
        Route("/api/cookie-login", cookie_login, methods=["POST"]),
        Route("/users", list_users),
    ])


def _client():
    c = LiveClient(Scope(["app.test"]), max_rps=0, allow_mutating=False)
    c._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_app()),
                                  follow_redirects=False)
    return c


def test_collection_path():
    assert collection_path("/users/{id}") == "/users"
    assert collection_path("/orgs/{oid}/members/:id") == "/orgs/{oid}/members"


def test_parse_spec_rejects_junk():
    assert parse_spec("not json") is None
    assert parse_spec('{"no":"url"}') is None
    assert parse_spec('{"url":"/login"}')["url"] == "/login"


@pytest.mark.asyncio
async def test_login_form_bearer_token():
    spec = {"url": "/api/login", "method": "POST", "content": "json",
            "body": {"username": "a", "password": "pw-A"},
            "apply": "bearer", "token_path": "data.token"}
    async with _client() as c:
        ident = await perform_login(c, "http://app.test", "userA", False, spec)
    assert ident.usable and ident.headers["Authorization"] == "Bearer TOK-A"


@pytest.mark.asyncio
async def test_login_form_cookie_and_failure():
    async with _client() as c:
        ok = await perform_login(c, "http://app.test", "userA", False,
                                 {"url": "/api/cookie-login", "apply": "cookie"})
        bad = await perform_login(c, "http://app.test", "userX", False,
                                  {"url": "/api/login", "apply": "bearer",
                                   "token_path": "data.token",
                                   "body": {"password": "wrong"}})
    assert ok.usable and ok.cookies["session"] == "SESS-A"
    assert not bad.usable and "401" in bad.note


@pytest.mark.asyncio
async def test_harvest_object_ids_from_list_endpoint():
    idA = Identity(role="userA", headers={"Authorization": "Bearer TOK-A"})
    endpoints = [{"id": "e0", "method": "GET", "path": "/users/{id}", "id_params": ["id"]}]
    async with _client() as c:
        seeds = await harvest_object_ids(c, "http://app.test", endpoints, [idA])
    assert seeds["userA"]["id"] == ["101", "102", "103"]

    merged = merge_seeds({"userA": {"id": ["999"]}}, seeds)
    assert merged["userA"]["id"] == ["999"]   # operator overrides harvested
