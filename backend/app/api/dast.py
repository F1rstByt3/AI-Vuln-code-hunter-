"""DAST: manage live-test targets & credentials, and launch authorized runs.

Live testing sends traffic to a *running* system, so these endpoints are
admin-gated, secrets are write-only, and starting a run requires an explicit
authorization attestation that is recorded on the run (who + when).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_arq, get_or_404
from app.auth import CurrentUser, require_role
from app.dast import store
from app.dast.client import smoke_test
from app.dast.identity import Identity
from app.dast.scope import Scope
from app.db import get_session
from app.models import (
    DastCredential, DastRun, DastStatus, DastTarget, Project, Role, Scan,
)
from app.schemas import (
    DastCredentialIn, DastCredentialOut, DastRunCreate, DastRunOut,
    DastTargetIn, DastTargetOut, DastTargetUpdate,
)

router = APIRouter(tags=["dast"])


# --------------------------------------------------------------------------- targets
@router.get("/projects/{project_id}/dast-targets", response_model=list[DastTargetOut])
async def list_targets(project_id: str, session: AsyncSession = Depends(get_session)):
    await get_or_404(session, Project, project_id)
    return await store.list_targets(session, project_id)


@router.post("/projects/{project_id}/dast-targets", response_model=DastTargetOut,
             dependencies=[Depends(require_role(Role.admin))])
async def create_target(project_id: str, body: DastTargetIn,
                        session: AsyncSession = Depends(get_session)):
    await get_or_404(session, Project, project_id)
    try:
        return await store.create_target(session, project_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/dast-targets/{target_id}", response_model=DastTargetOut,
            dependencies=[Depends(require_role(Role.admin))])
async def update_target(target_id: str, body: DastTargetUpdate,
                        session: AsyncSession = Depends(get_session)):
    t = await get_or_404(session, DastTarget, target_id)
    try:
        return await store.update_target(session, t, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/dast-targets/{target_id}", status_code=204,
               dependencies=[Depends(require_role(Role.admin))])
async def delete_target(target_id: str, session: AsyncSession = Depends(get_session)):
    t = await get_or_404(session, DastTarget, target_id)
    await session.delete(t)
    await session.commit()


# --------------------------------------------------------------------------- credentials
@router.post("/dast-targets/{target_id}/credentials", response_model=DastCredentialOut,
             dependencies=[Depends(require_role(Role.admin))])
async def add_credential(target_id: str, body: DastCredentialIn,
                         session: AsyncSession = Depends(get_session)):
    await get_or_404(session, DastTarget, target_id)
    try:
        return await store.add_credential(session, target_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/dast-credentials/{cred_id}", response_model=DastCredentialOut,
            dependencies=[Depends(require_role(Role.admin))])
async def update_credential(cred_id: str, body: DastCredentialIn,
                            session: AsyncSession = Depends(get_session)):
    c = await get_or_404(session, DastCredential, cred_id)
    try:
        return await store.update_credential(session, c, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/dast-credentials/{cred_id}", status_code=204,
               dependencies=[Depends(require_role(Role.admin))])
async def delete_credential(cred_id: str, session: AsyncSession = Depends(get_session)):
    c = await get_or_404(session, DastCredential, cred_id)
    await session.delete(c)
    await session.commit()


# --------------------------------------------------------------------------- test
@router.post("/dast-targets/{target_id}/test",
             dependencies=[Depends(require_role(Role.admin))])
async def test_target(target_id: str, session: AsyncSession = Depends(get_session)):
    """Connectivity + credential smoke test: one GET to the base URL per role.
    No scanning, no path probing."""
    t = await get_or_404(session, DastTarget, target_id)
    creds = (await session.execute(
        select(DastCredential).where(DastCredential.target_id == target_id)
    )).scalars().all()
    identities = [Identity.from_credential(c) for c in creds]
    scope = Scope(t.allowed_hosts or [])
    return await smoke_test(t.base_url, scope, identities)


# --------------------------------------------------------------------------- runs
@router.post("/scans/{scan_id}/dast", response_model=DastRunOut,
             dependencies=[Depends(require_role(Role.admin))])
async def launch_run(scan_id: str, body: DastRunCreate,
                     session: AsyncSession = Depends(get_session),
                     user: CurrentUser = Depends(require_role(Role.admin))):
    """Launch an authorized live-testing run confirming this scan's findings."""
    scan = await get_or_404(session, Scan, scan_id)
    target = await get_or_404(session, DastTarget, body.target_id)
    if target.project_id != scan.project_id:
        raise HTTPException(400, "target belongs to a different project")
    if not body.authorize:
        raise HTTPException(
            400, "authorization required: confirm you are permitted to test "
            f"{target.base_url} before launching a live run")
    if body.active_scan and not target.active_scan_enabled:
        raise HTTPException(400, "active scan is not enabled for this target")

    run = DastRun(
        scan_id=scan_id, target_id=target.id, status=DastStatus.queued,
        authorized_by=user.email, authorized_at=datetime.now(timezone.utc),
        allow_mutating=bool(body.allow_mutating),
        config={"active_scan": bool(body.active_scan),
                "allowed_hosts": target.allowed_hosts or []},
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)

    arq = await get_arq()
    await arq.enqueue_job("run_dast", run.id)
    return run


@router.get("/dast-runs/{run_id}", response_model=DastRunOut)
async def get_run(run_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, DastRun, run_id)


@router.post("/dast-runs/{run_id}/cancel", response_model=DastRunOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def cancel_run(run_id: str, session: AsyncSession = Depends(get_session)):
    from app import control
    run = await get_or_404(session, DastRun, run_id)
    if run.status in (DastStatus.queued, DastStatus.running):
        await control.set_control(run.scan_id + ":dast", "cancel")
        run.status = DastStatus.canceled
        run.finished_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(run)
    return run


@router.get("/scans/{scan_id}/dast-runs", response_model=list[DastRunOut])
async def list_runs(scan_id: str, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(DastRun).where(DastRun.scan_id == scan_id).order_by(DastRun.created_at.desc())
    )).scalars().all()
    return rows
