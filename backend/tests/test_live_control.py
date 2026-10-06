"""Live, in-flight control of a DAST run: pause, throttle, tighten (mutating
off / path exclude) and per-request intercept — all gated before a request
leaves, all tighten-only."""

from __future__ import annotations

import asyncio

import pytest

from app.control import ScanCanceledSignal
from app.dast import live_control
from app.dast.client import LiveClient
from app.dast.identity import Identity
from app.dast.live_control import LiveControl
from app.dast.scope import Scope


class _FakeRedis:
    """Minimal in-memory async Redis supporting what live_control/control use."""

    store: dict = {}
    hashes: dict = {}

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, ex=None):
        self.store[k] = v

    async def delete(self, *ks):
        for k in ks:
            self.store.pop(k, None)
            self.hashes.pop(k, None)

    async def hset(self, k, f, v):
        self.hashes.setdefault(k, {})[f] = v

    async def hget(self, k, f):
        return self.hashes.get(k, {}).get(f)

    async def hgetall(self, k):
        return dict(self.hashes.get(k, {}))

    async def hdel(self, k, f):
        self.hashes.get(k, {}).pop(f, None)

    async def expire(self, k, ex):
        pass

    async def aclose(self):
        pass


@pytest.fixture
def fake_redis(monkeypatch):
    _FakeRedis.store = {}
    _FakeRedis.hashes = {}
    r = _FakeRedis()
    monkeypatch.setattr(live_control, "_redis", lambda: r)
    import app.control as control
    monkeypatch.setattr(control, "_redis", lambda: r)
    return r


def _ident():
    return Identity.anonymous()


def _client(ctl, allow_mutating=True):
    return LiveClient(Scope(["app.test"]), max_rps=0, allow_mutating=allow_mutating,
                      control=ctl)


@pytest.mark.asyncio
async def test_patch_is_tighten_only(fake_redis):
    await live_control.write_patch("r1", {"status": "running"}, launch_max_rps=5)
    # rate can be lowered, never raised above the launch ceiling
    doc = await live_control.write_patch("r1", {"max_rps": 20}, launch_max_rps=5)
    assert doc["max_rps"] == 5
    doc = await live_control.write_patch("r1", {"max_rps": 1}, launch_max_rps=5)
    assert doc["max_rps"] == 1
    # mutating can only be turned off, re-enabling is ignored
    doc = await live_control.write_patch("r1", {"allow_mutating": False})
    assert doc["allow_mutating"] is False
    doc = await live_control.write_patch("r1", {"allow_mutating": True})
    assert doc["allow_mutating"] is False
    # exclude paths are additive
    await live_control.write_patch("r1", {"exclude_paths": ["/a"]})
    doc = await live_control.write_patch("r1", {"exclude_paths": ["/b", "/a"]})
    assert doc["exclude_paths"] == ["/a", "/b"]


@pytest.mark.asyncio
async def test_cancel_raises_through_gate(fake_redis):
    ctl = LiveControl("r2", "s2", _emit, launch_max_rps=5)
    await live_control.write_patch("r2", {"status": "canceled"})
    with pytest.raises(ScanCanceledSignal):
        await ctl.gate("GET", "http://app.test/x", "probe", "none", False)


@pytest.mark.asyncio
async def test_exclude_and_mutating_tighten_skip(fake_redis):
    ctl = LiveControl("r3", "s3", _emit, launch_max_rps=5)
    await live_control.write_patch("r3", {"exclude_paths": ["/admin"],
                                          "allow_mutating": False})
    assert await ctl.gate("GET", "http://app.test/admin/x", "probe", "none", False) == "skip"
    assert await ctl.gate("GET", "http://app.test/ok", "probe", "none", False) == "send"
    assert await ctl.gate("POST", "http://app.test/ok", "probe", "none", True) == "skip"
    # internal traffic (login/harvest) is never skipped by tighten rules
    assert await ctl.gate("POST", "http://app.test/admin/login", "login", "u", True) == "send"


@pytest.mark.asyncio
async def test_pause_blocks_then_resume(fake_redis):
    ctl = LiveControl("r4", "s4", _emit, launch_max_rps=5)
    await live_control.write_patch("r4", {"status": "paused"})
    live_control._PAUSE_POLL = 0.02

    async def resume_later():
        await asyncio.sleep(0.1)
        await live_control.write_patch("r4", {"status": "running"})

    task = asyncio.create_task(resume_later())
    res = await asyncio.wait_for(
        ctl.gate("GET", "http://app.test/x", "probe", "none", False), timeout=2)
    await task
    assert res == "send"


@pytest.mark.asyncio
async def test_intercept_holds_until_decision(fake_redis):
    ctl = LiveControl("r5", "s5", _emit, launch_max_rps=5)
    live_control._DECISION_POLL = 0.02
    await live_control.write_patch("r5", {"intercept": "all"})

    async def approve_later():
        await asyncio.sleep(0.08)
        pend = await live_control.list_pending("r5")
        assert pend and pend[0]["method"] == "GET"
        await live_control.set_decision("r5", pend[0]["seq"], "allow")

    task = asyncio.create_task(approve_later())
    res = await asyncio.wait_for(
        ctl.gate("GET", "http://app.test/x", "probe", "none", False), timeout=2)
    await task
    assert res == "send"
    assert await live_control.list_pending("r5") == []        # cleaned up


@pytest.mark.asyncio
async def test_intercept_skip_rest_turns_off(fake_redis):
    ctl = LiveControl("r6", "s6", _emit, launch_max_rps=5)
    live_control._DECISION_POLL = 0.02
    await live_control.write_patch("r6", {"intercept": "mutating"})

    async def decide():
        await asyncio.sleep(0.06)
        pend = await live_control.list_pending("r6")
        await live_control.set_decision("r6", pend[0]["seq"], "skip_rest")

    task = asyncio.create_task(decide())
    res = await asyncio.wait_for(
        ctl.gate("DELETE", "http://app.test/x", "probe", "none", True), timeout=2)
    await task
    assert res == "skip"
    doc = await live_control.read_doc("r6")
    assert doc["intercept"] == "off"       # subsequent requests flow freely


@pytest.mark.asyncio
async def test_client_send_skips_when_gated(fake_redis):
    ctl = LiveControl("r7", "s7", _emit, launch_max_rps=5)
    await live_control.write_patch("r7", {"exclude_paths": ["/x"]})
    client = _client(ctl)
    resp = await client.send("GET", "http://app.test/x", _ident())
    assert resp.error == "skipped by live control" and client.count == 0
    await client._client.aclose()


@pytest.mark.asyncio
async def test_live_rps_override_reaches_client(fake_redis):
    ctl = LiveControl("r8", "s8", _emit, launch_max_rps=5)
    client = _client(ctl)
    assert client._min_interval == 0.0
    await live_control.write_patch("r8", {"max_rps": 2}, launch_max_rps=5)
    ctl._doc_at = 0.0                      # force re-read on next gate
    await ctl.gate("GET", "http://app.test/ok", "probe", "none", False)
    assert client._min_interval == 0.5     # 1 / 2rps
    await client._client.aclose()


async def _emit(_e):
    return None
