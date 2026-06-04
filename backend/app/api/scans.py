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
    Artifact, Finding, Project, Role, Scan, ScanCheckpoint, ScanStatus, Severity,
)
from app.schemas import FindingOut, ScanControl, ScanCreate, ScanOut, ScanRerun
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
    scan = Scan(
        project_id=project_id,
        artifact_id=body.artifact_id,
        status=ScanStatus.queued,
        config={
            "scanners": body.scanners, "instructions": body.instructions,
            "model": body.model, "file_paths": body.file_paths,
            "review_scope": body.review_scope,
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
    # A queued (not-yet-started) scan won't reach a checkpoint, so cancel it now.
    if action == "cancel" and scan.status == ScanStatus.queued:
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
