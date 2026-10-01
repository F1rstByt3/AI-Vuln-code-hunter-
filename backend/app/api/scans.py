"""Scans: kick off and inspect analysis runs."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import control, events
from app.api.deps import get_arq, get_or_404
from app.auth import require_role
from app.db import get_session
from fastapi import HTTPException, status as http_status

from sqlalchemy import func

from app.models import (
    AiProfile, Artifact, Finding, Project, Role, Scan, ScanCheckpoint, ScanStatus, Severity,
)
from app.schemas import FindingOut, ScanChecks, ScanControl, ScanCreate, ScanOut, ScanRerun
from app.worker import RERUNNABLE_STAGES

router = APIRouter(tags=["scans"])


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
async def list_scans(project_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
        )
    ).scalars().all()
    return rows


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanOut,
    dependencies=[Depends(require_role(Role.reviewer))],
)
async def create_scan(
    project_id: str, body: ScanCreate, session: AsyncSession = Depends(get_session)
):
    await get_or_404(session, Project, project_id)
    await get_or_404(session, Artifact, body.artifact_id)
    profile_name = None
    if body.profile_id:
        profile_name = (await get_or_404(session, AiProfile, body.profile_id)).name
    checks = (body.checks or ScanChecks()).model_dump()
    scan = Scan(
        project_id=project_id,
        artifact_id=body.artifact_id,
        status=ScanStatus.queued,
        config={
            "scanners": body.scanners, "instructions": body.instructions,
            "model": body.model, "file_paths": body.file_paths,
            "review_scope": body.review_scope,
            "profile_id": body.profile_id, "profile_name": profile_name,
            "checks": checks,
        },
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    arq = await get_arq()
    await arq.enqueue_job("run_scan", scan.id)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, Scan, scan_id)


@router.post("/scans/{scan_id}/rerun", response_model=ScanOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def rerun_scan_stage(
    scan_id: str, body: ScanRerun, session: AsyncSession = Depends(get_session)
):
    """Re-run a single pipeline stage (semgrep | sonarqube | ai) on this scan,
    replacing just that stage's findings."""
    scan = await get_or_404(session, Scan, scan_id)
    if body.stage not in RERUNNABLE_STAGES:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST,
            f"stage must be one of {', '.join(RERUNNABLE_STAGES)}",
        )
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        raise HTTPException(http_status.HTTP_409_CONFLICT, "scan is already running")
    scan.status = ScanStatus.queued
    scan.error = None
    await session.commit()
    await session.refresh(scan)

    arq = await get_arq()
    await arq.enqueue_job("rerun_stage", scan.id, body.stage)
    return scan


@router.get("/scans/{scan_id}/diff")
async def scan_diff(scan_id: str, against: str | None = None,
                    session: AsyncSession = Depends(get_session)):
    """Diff this scan's findings against an earlier scan's — new / fixed /
    still-open issues, for tracking remediation. Baseline defaults to the most
    recent earlier scan of the same project (override with ?against=<scan_id>)."""
    from app.diffing import diff_findings

    scan = await get_or_404(session, Scan, scan_id)
    if against:
        baseline = await get_or_404(session, Scan, against)
    else:
        baseline = (await session.execute(
            select(Scan).where(
                Scan.project_id == scan.project_id,
                Scan.id != scan.id,
                Scan.created_at < scan.created_at,
            ).order_by(Scan.created_at.desc()).limit(1)
        )).scalar_one_or_none()
    if baseline is None:
        return {"baseline": None, "counts": {"new": 0, "fixed": 0, "still_open": 0},
                "new": [], "fixed": [], "still_open": []}
    cur = (await session.execute(
        select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    base = (await session.execute(
        select(Finding).where(Finding.scan_id == baseline.id))).scalars().all()
    result = diff_findings(cur, base)
    result["baseline"] = {"id": baseline.id, "created_at": baseline.created_at.isoformat()
                          if baseline.created_at else None}
    return result


@router.get("/scans/{scan_id}/resumable")
async def scan_resumable(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Report whether an interrupted scan has durable checkpoints to resume from,
    with a per-phase count of completed work units (reviewer batches, judge
    chunks, exploit batches)."""
    await get_or_404(session, Scan, scan_id)
    rows = (await session.execute(
        select(ScanCheckpoint.phase, func.count())
        .where(ScanCheckpoint.scan_id == scan_id)
        .group_by(ScanCheckpoint.phase)
    )).all()
    completed = {phase: int(n) for phase, n in rows}
    work = {k: v for k, v in completed.items() if k != "inputs"}
    return {"resumable": bool(work), "completed": completed}


@router.post("/scans/{scan_id}/resume", response_model=ScanOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def resume_scan_endpoint(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Resume an interrupted scan's AI pipeline, skipping work units already
    checkpointed to the DB (so a crash/Docker-stop mid-review doesn't re-spend)."""
    scan = await get_or_404(session, Scan, scan_id)
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        # A second job on the same scan would race the first (duplicate work,
        # clobbered checkpoints) — only resume a scan that has stopped.
        raise HTTPException(http_status.HTTP_409_CONFLICT, "scan is already running")
    has_ckpt = (await session.execute(
        select(ScanCheckpoint.id).where(ScanCheckpoint.scan_id == scan_id).limit(1)
    )).first() is not None
    if not has_ckpt:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST,
            "nothing to resume — no checkpoints saved for this scan",
        )
    scan.status = ScanStatus.queued
    scan.error = None
    await session.commit()
    await session.refresh(scan)

    arq = await get_arq()
    await arq.enqueue_job("resume_scan", scan.id)
    return scan


@router.post("/scans/{scan_id}/control", response_model=ScanOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def control_scan(
    scan_id: str, body: ScanControl, session: AsyncSession = Depends(get_session)
):
    """Cooperative control of a running scan: pause | resume | skip | cancel.

    The worker polls a Redis flag at stage/batch checkpoints and reacts. Pause
    holds at the next checkpoint; skip abandons the current stage; cancel stops
    the whole run.
    """
    scan = await get_or_404(session, Scan, scan_id)
    action = body.action
    if action not in control.CONTROL_ACTIONS:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST,
            f"action must be one of {', '.join(sorted(control.CONTROL_ACTIONS))}",
        )
    if scan.status not in (ScanStatus.queued, ScanStatus.running):
        raise HTTPException(http_status.HTTP_409_CONFLICT, "scan is not running")

    await control.set_control(scan_id, action)
    await events.publish(scan_id, {"type": "control", "control": action})
    # Mark it canceled now (queued scans never reach a checkpoint; running ones
    # are interrupted by the worker's cancel watcher within ~2s).
    if action == "cancel":
        scan.status = ScanStatus.canceled
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(scan)
        await events.publish(scan_id, {"type": "canceled"})
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def cancel_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    scan = await get_or_404(session, Scan, scan_id)
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        # Signal the worker to stop cleanly at its next checkpoint…
        await control.set_control(scan_id, "cancel")
        # …and mark it canceled now so the UI updates immediately even if the
        # worker is between long operations or no longer running.
        scan.status = ScanStatus.canceled
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(scan)
        await events.publish(scan_id, {"type": "canceled"})
    return scan


@router.delete("/scans/{scan_id}", status_code=204,
               dependencies=[Depends(require_role(Role.admin))])
async def delete_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Delete a scan and everything it produced (findings, events, checkpoints,
    live-test runs). Refuses a running scan — cancel it first. The artifact and
    its working tree are left intact for other scans."""
    scan = await get_or_404(session, Scan, scan_id)
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        raise HTTPException(http_status.HTTP_409_CONFLICT,
                            "cancel the scan before deleting it")
    try:
        await control.clear_control(scan_id)   # drop any stale cancel key
    except Exception:  # noqa: BLE001 — redis down shouldn't block a delete
        pass
    await session.delete(scan)
    await session.commit()


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: str,
    severity: Severity | None = None,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = (await session.execute(stmt)).scalars().all()
    # critical-first ordering
    order = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "info"])}
    return sorted(rows, key=lambda f: order.get(f.severity.value, 99))
