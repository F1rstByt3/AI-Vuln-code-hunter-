"""ORM models.

Hierarchy:  Client -> Project -> Artifact (a code snapshot) -> Scan -> Finding.
Plus: MCP server registry, chat messages, and a replayable agent-event log.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


# --------------------------------------------------------------------------- enums
class ArtifactKind(str, enum.Enum):
    upload = "upload"      # uploaded archive / files
    git = "git"            # linked git repo + commit
    local = "local"        # path mounted on the worker (air-gapped)


class ArtifactStatus(str, enum.Enum):
    pending = "pending"
    ingesting = "ingesting"
    ready = "ready"
    failed = "failed"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    needs_review = "needs_review"   # finished but has human-verification items
    completed = "completed"
    failed = "failed"
    canceled = "canceled"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingState(str, enum.Enum):
    proposed = "proposed"
    confirmed = "confirmed"
    dismissed = "dismissed"        # false positive / accepted risk
    needs_info = "needs_info"      # routed to a human (business logic / uncertain)


class FindingSource(str, enum.Enum):
    semgrep = "semgrep"
    sonarqube = "sonarqube"
    ai = "ai"
    correlated = "correlated"      # AI-confirmed a static-tool candidate


class Role(str, enum.Enum):
    admin = "admin"
    reviewer = "reviewer"
    viewer = "viewer"


# --------------------------------------------------------------------------- core
class User(Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(200))
    oid: Mapped[str | None] = mapped_column(String(64), index=True)  # Entra object id
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.reviewer)


class Client(Base):
    __tablename__ = "clients"
    name: Mapped[str] = mapped_column(String(200), index=True)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    contact_email: Mapped[str | None] = mapped_column(String(320))
    notes: Mapped[str | None] = mapped_column(Text)
    projects: Mapped[list[Project]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    repo_url: Mapped[str | None] = mapped_column(String(500))
    default_branch: Mapped[str] = mapped_column(String(120), default="main")

    client: Mapped[Client] = relationship(back_populates="projects")
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    scans: Mapped[list[Scan]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Artifact(Base):
    """An immutable snapshot of code attached to a project."""

    __tablename__ = "artifacts"
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[ArtifactKind] = mapped_column(Enum(ArtifactKind))
    status: Mapped[ArtifactStatus] = mapped_column(
        Enum(ArtifactStatus), default=ArtifactStatus.pending
    )
    label: Mapped[str | None] = mapped_column(String(200))
    source_ref: Mapped[str | None] = mapped_column(String(500))  # commit sha / url / local path
    storage_key: Mapped[str | None] = mapped_column(String(500))  # object-store prefix
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    analyzable_count: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="artifacts")
    files: Mapped[list[ArtifactFile]] = relationship(
        back_populates="artifact", cascade="all, delete-orphan"
    )


class ArtifactFile(Base):
    """File index produced during ingestion (the 'analyzable surface')."""

    __tablename__ = "artifact_files"
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(1024), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    language: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    is_binary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_vendored: Mapped[bool] = mapped_column(Boolean, default=False)
    included: Mapped[bool] = mapped_column(Boolean, default=True)  # in analysis surface?

    artifact: Mapped[Artifact] = relationship(back_populates="files")


class Scan(Base):
    """A single analysis run over an artifact."""

    __tablename__ = "scans"
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)
    config: Mapped[dict] = mapped_column(JSON, default=dict)   # scanners, model, budget
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # counts, risk score
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list[AgentEvent]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.medium, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0..1
    source: Mapped[FindingSource] = mapped_column(Enum(FindingSource), default=FindingSource.ai)
    state: Mapped[FindingState] = mapped_column(
        Enum(FindingState), default=FindingState.proposed, index=True
    )

    cwe: Mapped[str | None] = mapped_column(String(40))     # e.g. CWE-89
    owasp: Mapped[str | None] = mapped_column(String(40))   # e.g. A03:2021
    category: Mapped[str | None] = mapped_column(String(120))

    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    code_snippet: Mapped[str | None] = mapped_column(Text)   # evidence
    remediation: Mapped[str | None] = mapped_column(Text)

    # Human-in-the-loop
    human_question: Mapped[str | None] = mapped_column(Text)   # set when state == needs_info
    triage_note: Mapped[str | None] = mapped_column(Text)
    triaged_by: Mapped[str | None] = mapped_column(String(320))
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    scan: Mapped[Scan] = relationship(back_populates="findings")


class McpServer(Base):
    """Registered MCP server (Semgrep / SonarQube / custom) exposed to the agent."""

    __tablename__ = "mcp_servers"
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )  # null => workspace-wide
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(40))        # semgrep | sonarqube | custom
    transport: Mapped[str] = mapped_column(String(20), default="stdio")  # stdio | http | sse
    url: Mapped[str | None] = mapped_column(String(500))
    command: Mapped[dict] = mapped_column(JSON, default=dict)   # {"cmd": "...", "args": [...]}
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)    # secret refs live in Key Vault


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20))   # user | assistant | system | tool
    content: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    scan: Mapped[Scan] = relationship(back_populates="messages")


class Setting(Base):
    """Runtime key/value config editable from the app (e.g. Foundry endpoint, key,
    selected model). Layered OVER .env defaults. Secret values are write-only via
    the API (returned masked). In prod the API key should be backed by Key Vault."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class AgentEvent(Base):
    """Append-only, replayable log of everything the agent streamed for a scan."""

    __tablename__ = "agent_events"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    type: Mapped[str] = mapped_column(String(30))  # status|log|token|finding|tool_call|question
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    scan: Mapped[Scan] = relationship(back_populates="events")


class ScanCheckpoint(Base):
    """Durable, resumable checkpoint of completed AI-pipeline work units.

    Each row holds the result of one finished unit — a reviewer batch, a judge
    chunk, an exploit batch, or the pipeline's frozen inputs — keyed by
    (scan_id, phase, chunk_key). On resume the worker reloads these and skips
    any unit already present, so a crash/restart at batch 657 picks up where it
    left off instead of paying for the whole reviewer phase again. Cleared on a
    clean finish (and at the start of a fresh run)."""

    __tablename__ = "scan_checkpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "phase", "chunk_key", name="uq_checkpoint_unit"),
    )
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    phase: Mapped[str] = mapped_column(String(20))   # inputs | review | judge | exploit
    chunk_key: Mapped[str] = mapped_column(String(200))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
