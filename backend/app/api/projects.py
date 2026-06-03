"""Project endpoints + the per-project vulnerability dashboard."""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.auth import require_role
from app.db import get_session
from app.models import Client, Finding, FindingState, Project, Role, Scan
from app.schemas import (
    DashboardSummary,
    ProjectCreate,
    ProjectOut,
    ScanOut,
    SeverityBreakdown,
)

router = APIRouter(tags=["projects"])


@router.get("/clients/{client_id}/projects", response_model=list[ProjectOut])
async def list_projects(client_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(select(Project).where(Project.client_id == client_id))
    ).scalars().all()
    return rows


@router.post(
    "/clients/{client_id}/projects",
    response_model=ProjectOut,
    dependencies=[Depends(require_role(Role.reviewer))],
)
async def create_project(
    client_id: str, body: ProjectCreate, session: AsyncSession = Depends(get_session)
):
    await get_or_404(session, Client, client_id)
    project = Project(client_id=client_id, **body.model_dump())
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
async def get_project(project_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, Project, project_id)


@router.delete(
    "/projects/{project_id}", status_code=204, dependencies=[Depends(require_role(Role.admin))]
)
async def delete_project(project_id: str, session: AsyncSession = Depends(get_session)):
    project = await get_or_404(session, Project, project_id)
    await session.delete(project)
    await session.commit()


@router.get("/projects/{project_id}/dashboard", response_model=DashboardSummary)
async def project_dashboard(project_id: str, session: AsyncSession = Depends(get_session)):
    await get_or_404(session, Project, project_id)
    latest = (
        await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
        )
    ).scalars().first()

    if latest is None:
        return DashboardSummary(
            project_id=project_id, total_findings=0, open_findings=0, needs_review=0,
            risk_score=0.0, by_severity=SeverityBreakdown(), by_category={}, top_files=[],
        )

    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == latest.id))
    ).scalars().all()

    sev = Counter(f.severity.value for f in findings)
    cat = Counter((f.category or "uncategorized") for f in findings)
    files = Counter(f.file_path for f in findings if f.file_path)
    open_f = sum(1 for f in findings if f.state != FindingState.dismissed)
    needs = sum(1 for f in findings if f.state == FindingState.needs_info)

    return DashboardSummary(
        project_id=project_id,
        total_findings=len(findings),
        open_findings=open_f,
        needs_review=needs,
        risk_score=float((latest.summary or {}).get("risk_score", 0.0)),
        by_severity=SeverityBreakdown(**{k: sev.get(k, 0) for k in
                                         ["critical", "high", "medium", "low", "info"]}),
        by_category=dict(cat.most_common(12)),
        top_files=[{"path": p, "count": n} for p, n in files.most_common(10)],
        latest_scan=ScanOut.model_validate(latest),
    )
