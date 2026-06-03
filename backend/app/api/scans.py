"""Scans: kick off and inspect analysis runs."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import events
from app.api.deps import get_arq, get_or_404
from app.auth import require_role
from app.db import get_session
from app.models import Artifact, Finding, Project, Role, Scan, ScanStatus, Severity
from app.schemas import FindingOut, ScanCreate, ScanOut

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


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def cancel_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    scan = await get_or_404(session, Scan, scan_id)
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        scan.status = ScanStatus.canceled
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
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
