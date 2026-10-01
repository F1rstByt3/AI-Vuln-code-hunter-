"""Artifacts: code snapshots attached to a project.

Three ingestion paths:
  * upload  — resumable multipart upload to object storage (handles 10GB+);
  * git     — clone url[#ref] at scan time;
  * local   — a path mounted on the worker (air-gapped review).

Uploads use init -> upload parts -> complete, so a giant file survives network
blips and never lands fully in API memory.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.auth import require_role
from app.config import settings
from app.db import get_session
from app.models import Artifact, ArtifactFile, ArtifactKind, Project, Role
from app.schemas import (
    ArtifactCreate,
    ArtifactFileOut,
    ArtifactOut,
    UploadComplete,
    UploadInit,
    UploadInitOut,
)
from app.storage import get_storage

router = APIRouter(tags=["artifacts"])


@router.get("/projects/{project_id}/artifacts", response_model=list[ArtifactOut])
async def list_artifacts(project_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Artifact).where(Artifact.project_id == project_id)
            .order_by(Artifact.created_at.desc())
        )
    ).scalars().all()
    return rows


@router.post(
    "/projects/{project_id}/artifacts",
    response_model=ArtifactOut,
    dependencies=[Depends(require_role(Role.reviewer))],
)
async def create_artifact(
    project_id: str, body: ArtifactCreate, session: AsyncSession = Depends(get_session)
):
    """Register a git or local artifact (materialised at scan time)."""
    await get_or_404(session, Project, project_id)
    artifact = Artifact(
        project_id=project_id, kind=body.kind, label=body.label, source_ref=body.source_ref
    )
    session.add(artifact)
    await session.commit()
    await session.refresh(artifact)
    return artifact


@router.post(
    "/projects/{project_id}/uploads",
    response_model=UploadInitOut,
    dependencies=[Depends(require_role(Role.reviewer))],
)
async def init_upload(
    project_id: str, body: UploadInit, session: AsyncSession = Depends(get_session)
):
    await get_or_404(session, Project, project_id)
    if body.size_bytes > settings.max_upload_bytes:
        from fastapi import HTTPException

        raise HTTPException(413, "file exceeds max upload size")
    artifact = Artifact(
        # Assign the id now: the default only fires at flush, so the storage key
        # below used to read ".../None/<filename>" and uploads could collide.
        id=str(uuid.uuid4()),
        project_id=project_id, kind=ArtifactKind.upload, label=body.filename,
        size_bytes=body.size_bytes,
        meta={"filename": body.filename, "declared_size": body.size_bytes},
    )
    artifact.storage_key = f"artifacts/{project_id}/{artifact.id}/{body.filename}"
    session.add(artifact)
    await session.flush()

    upload_id = await get_storage().create_multipart(artifact.storage_key)
    artifact.meta = {**artifact.meta, "upload_id": upload_id}
    await session.commit()
    return UploadInitOut(
        artifact_id=artifact.id, upload_id=upload_id, chunk_bytes=settings.upload_chunk_bytes
    )


@router.put("/uploads/{artifact_id}/parts/{part}", dependencies=[Depends(require_role(Role.reviewer))])
async def upload_part(
    artifact_id: str, part: int, upload_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
):
    artifact = await get_or_404(session, Artifact, artifact_id)
    body = await request.body()
    etag = await get_storage().upload_part(artifact.storage_key, upload_id, part, body)
    return {"part": part, "etag": etag}


@router.post("/uploads/{artifact_id}/complete", response_model=ArtifactOut,
             dependencies=[Depends(require_role(Role.reviewer))])
async def complete_upload(
    artifact_id: str, body: UploadComplete, session: AsyncSession = Depends(get_session)
):
    artifact = await get_or_404(session, Artifact, artifact_id)
    await get_storage().complete_multipart(artifact.storage_key, body.upload_id, body.parts)
    await session.refresh(artifact)
    return artifact


@router.get("/artifacts/{artifact_id}", response_model=ArtifactOut)
async def get_artifact(artifact_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, Artifact, artifact_id)


@router.get("/artifacts/{artifact_id}/files", response_model=list[ArtifactFileOut])
async def list_artifact_files(
    artifact_id: str, included_only: bool = False, limit: int = 50000,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(ArtifactFile).where(ArtifactFile.artifact_id == artifact_id)
    if included_only:
        stmt = stmt.where(ArtifactFile.included.is_(True))
    stmt = stmt.order_by(ArtifactFile.path)
    rows = (await session.execute(stmt.limit(limit))).scalars().all()
    return rows


async def purge_artifact_storage(artifact: Artifact) -> None:
    """Best-effort removal of an artifact's blob + materialised workdir. The DB
    rows (files, scans, findings…) are removed by the cascading delete; this
    reclaims the object store and local disk they left behind. Never raises."""
    import os
    import shutil

    from app.ingestion import WORKROOT

    if artifact.storage_key:
        try:
            await get_storage().delete_object(artifact.storage_key)
        except Exception:  # noqa: BLE001 — object may already be gone
            pass
    # Workdir is WORKROOT/<artifact id>; only remove paths safely under it.
    workdir = os.path.join(WORKROOT, artifact.id)
    root = os.path.realpath(WORKROOT)
    target = os.path.realpath(workdir)
    if target.startswith(root + os.sep) and os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)


@router.delete("/artifacts/{artifact_id}", status_code=204,
               dependencies=[Depends(require_role(Role.admin))])
async def delete_artifact(artifact_id: str, session: AsyncSession = Depends(get_session)):
    """Delete an uploaded/linked artifact: its stored blob, its working tree,
    and — by cascade — every scan, finding and event produced from it."""
    from app.models import Scan

    artifact = await get_or_404(session, Artifact, artifact_id)
    await purge_artifact_storage(artifact)
    # Delete dependent scans through the ORM so their findings/events/runs are
    # removed via relationship cascades (DB ON DELETE CASCADE covers Postgres,
    # but SQLite in tests needs the explicit delete).
    scans = (await session.execute(
        select(Scan).where(Scan.artifact_id == artifact_id))).scalars().all()
    for sc in scans:
        await session.delete(sc)
    await session.delete(artifact)
    await session.commit()
