"""Findings: inspect and triage (the human-in-the-loop state machine)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.auth import CurrentUser, require_role
from app.db import get_session
from app.models import Finding, Role
from app.schemas import FindingOut, FindingTriage

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, Finding, finding_id)


@router.post("/{finding_id}/triage", response_model=FindingOut)
async def triage_finding(
    finding_id: str,
    body: FindingTriage,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_role(Role.reviewer)),
):
    """Confirm / dismiss / route a finding. Decisions persist and inform later scans."""
    finding = await get_or_404(session, Finding, finding_id)
    finding.state = body.state
    finding.triage_note = body.triage_note
    finding.triaged_by = user.email
    finding.triaged_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(finding)
    return finding
