"""Creating DAST runs — shared by the manual API launch and automatic
post-scan runs, so both honour the target's mode policy identically."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dast.modes import check_allowed, normalize_mode
from app.models import DastRun, DastStatus, DastTarget, Scan


def _now() -> datetime:
    return datetime.now(UTC)


ACTIVE_RUN_STATES = (DastStatus.pending_approval, DastStatus.queued, DastStatus.running)


async def has_active_run(session: AsyncSession, scan_id: str) -> bool:
    row = (await session.execute(
        select(DastRun.id).where(DastRun.scan_id == scan_id,
                                 DastRun.status.in_(ACTIVE_RUN_STATES)).limit(1)
    )).first()
    return row is not None


async def create_run(session: AsyncSession, scan: Scan, target: DastTarget, *,
                     authorized_by: str, allow_mutating: bool = False,
                     access_control: bool = True, active_scan: bool = False,
                     include_paths: list[str] | None = None,
                     exclude_paths: list[str] | None = None,
                     intercept: str = "off", source: str = "manual") -> DastRun:
    """Create a run row honouring the target's mode (allowed checks + approval).

    Does NOT enqueue — the caller enqueues only when the returned run is
    ``queued`` (``pending_approval`` runs wait for :func:`approve_run`)."""
    mode = normalize_mode(target.mode_config)
    if active_scan and not check_allowed(mode, "active_scan"):
        raise ValueError("active scan is disabled for this target in its DAST mode settings")
    if intercept not in ("off", "mutating", "all"):
        intercept = "off"
    pending = mode["require_approval"]
    run = DastRun(
        scan_id=scan.id, target_id=target.id,
        status=DastStatus.pending_approval if pending else DastStatus.queued,
        authorized_by=authorized_by,
        authorized_at=None if pending else _now(),
        allow_mutating=bool(allow_mutating),
        config={"active_scan": bool(active_scan),
                "checks": {"access_control": bool(access_control),
                           "active_scan": bool(active_scan)},
                "include_paths": include_paths or [],
                "exclude_paths": exclude_paths or [],
                "intercept": intercept,
                "source": source,
                "allowed_hosts": target.allowed_hosts or []},
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)
    return run


async def approve_run(session: AsyncSession, run: DastRun, approver: str) -> DastRun:
    run.status = DastStatus.queued
    run.authorized_at = _now()
    run.config = {**(run.config or {}), "approved_by": approver}
    await session.commit()
    await session.refresh(run)
    return run
