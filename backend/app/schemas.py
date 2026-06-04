"""Pydantic request/response models (the public API contract)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import (
    ArtifactKind,
    ArtifactStatus,
    FindingSource,
    FindingState,
    ScanStatus,
    Severity,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    updated_at: datetime


# ---- Client ----
class ClientCreate(BaseModel):
    name: str
    slug: str | None = None
    contact_email: EmailStr | None = None
    notes: str | None = None


class ClientOut(ORMModel):
    name: str
    slug: str
    contact_email: str | None = None
    notes: str | None = None


# ---- Project ----
class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_url: str | None = None
    default_branch: str = "main"


class ProjectOut(ORMModel):
    client_id: str
    name: str
    description: str | None = None
    repo_url: str | None = None
    default_branch: str


# ---- Artifact / ingestion ----
class ArtifactCreate(BaseModel):
    kind: ArtifactKind
    label: str | None = None
    source_ref: str | None = None  # git url+ref, or local path


class ArtifactOut(ORMModel):
    project_id: str
    kind: ArtifactKind
    status: ArtifactStatus
    label: str | None = None
    source_ref: str | None = None
    size_bytes: int
    file_count: int
    analyzable_count: int
    error: str | None = None


class ArtifactFileOut(ORMModel):
    path: str
    size_bytes: int
    language: str | None = None
    is_binary: bool
    is_vendored: bool
    included: bool


class UploadInit(BaseModel):
    filename: str
    size_bytes: int


class UploadInitOut(BaseModel):
    artifact_id: str
    upload_id: str
    chunk_bytes: int


class UploadComplete(BaseModel):
    upload_id: str
    parts: list[dict]  # [{"part": 1, "etag": "..."}]


# ---- Scan ----
class ScanCreate(BaseModel):
    artifact_id: str
    scanners: list[str] = Field(default_factory=lambda: ["semgrep", "mcp", "ai"])
    instructions: str | None = None  # free-form steer for the agent
    model: str | None = None         # Foundry deployment override (else app default)
    file_paths: list[str] | None = None  # scope scan to these files/folders
    # "full" reviews every file; "targeted" reviews only files with static
    # candidates + endpoint handlers (much cheaper, may miss scanner-blind vulns)
    review_scope: str = "full"


class ScanRerun(BaseModel):
    stage: str  # semgrep | sonarqube | ai — re-run just this stage


class ScanControl(BaseModel):
    action: str  # pause | resume | skip | cancel


class ScanOut(ORMModel):
    project_id: str
    artifact_id: str
    status: ScanStatus
    config: dict
    summary: dict
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


# ---- Finding ----
class FindingOut(ORMModel):
    scan_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    source: FindingSource
    state: FindingState
    cwe: str | None = None
    owasp: str | None = None
    category: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    remediation: str | None = None
    human_question: str | None = None
    triage_note: str | None = None
    triaged_by: str | None = None
    raw: dict = {}


class FindingTriage(BaseModel):
    state: FindingState
    triage_note: str | None = None


# ---- MCP servers ----
class McpServerCreate(BaseModel):
    name: str
    kind: str = "custom"
    transport: str = "stdio"
    url: str | None = None
    command: dict = Field(default_factory=dict)
    enabled: bool = True
    config: dict = Field(default_factory=dict)


class McpServerOut(ORMModel):
    project_id: str | None = None
    name: str
    kind: str
    transport: str
    url: str | None = None
    enabled: bool


# ---- Chat ----
class ChatIn(BaseModel):
    content: str


class ChatOut(ORMModel):
    scan_id: str
    role: str
    content: str
    meta: dict


# ---- Settings (Foundry connection, editable in-app) ----
class ModelRoleOut(BaseModel):
    deployment: str
    transport: str = "auto"          # auto | chat | responses
    reasoning_effort: str | None = None


class ModelRolesOut(BaseModel):
    chat: ModelRoleOut | None = None
    reviewers: list[ModelRoleOut] = []
    judge: ModelRoleOut | None = None
    exploit: ModelRoleOut | None = None


class FoundrySettingsOut(BaseModel):
    endpoint: str | None = None
    deployment: str
    api_version: str
    api_style: str = "v1"
    use_agent_service: bool
    api_key_set: bool
    mock_mode: bool
    auth_mode: str
    roles: ModelRolesOut = ModelRolesOut()


class FoundrySettingsUpdate(BaseModel):
    endpoint: str | None = None
    api_key: str | None = None       # blank => leave existing secret unchanged
    deployment: str | None = None
    api_version: str | None = None
    api_style: str | None = None     # v1 | azure
    use_agent_service: bool | None = None
    roles: ModelRolesOut | None = None


class ScannerSettingsOut(BaseModel):
    semgrep_enabled: bool = True
    semgrep_ruleset: str = "auto"
    sonarqube_enabled: bool = False
    sonarqube_url: str | None = None
    sonarqube_token_set: bool = False


class ScannerSettingsUpdate(BaseModel):
    semgrep_enabled: bool | None = None
    semgrep_ruleset: str | None = None
    sonarqube_enabled: bool | None = None
    sonarqube_url: str | None = None
    sonarqube_token: str | None = None  # blank => leave existing secret unchanged


class ModelsOut(BaseModel):
    models: list[str]
    mock: bool


class ConnectionTest(BaseModel):
    ok: bool
    detail: str
    models: list[str] = Field(default_factory=list)


# ---- Dashboard ----
class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class EndpointOut(BaseModel):
    method: str
    path: str
    file_path: str
    line: int
    framework: str
    handler: str | None = None
    auth_hints: list[str] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    project_id: str
    total_findings: int
    open_findings: int
    needs_review: int
    risk_score: float
    by_severity: SeverityBreakdown
    by_category: dict[str, int]
    top_files: list[dict]
    latest_scan: ScanOut | None = None
    endpoints: list[EndpointOut] = Field(default_factory=list)
