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
class ScanChecks(BaseModel):
    coverage: bool = True        # re-triage unaddressed scanner hits + second look
    verify: bool = True          # adversarial false-positive verification
    access_control: bool = True  # endpoint authn/authz (BOLA/BFLA/IDOR) review


class ScanCreate(BaseModel):
    artifact_id: str
    scanners: list[str] = Field(default_factory=lambda: ["semgrep", "mcp", "ai"])
    instructions: str | None = None  # free-form steer for the agent
    model: str | None = None         # Foundry deployment override (else app default)
    file_paths: list[str] | None = None  # scope scan to these files/folders
    # "full" reviews every file; "targeted" reviews only files with static
    # candidates + endpoint handlers (much cheaper, may miss scanner-blind vulns)
    review_scope: str = "full"
    profile_id: str | None = None    # saved AI profile to use (else the active one)
    # Extra verification passes (all default on): coverage sweep, adversarial
    # false-positive verification, endpoint access-control review.
    checks: ScanChecks | None = None


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
    verifier: ModelRoleOut | None = None


class FoundrySettingsOut(BaseModel):
    endpoint: str | None = None
    deployment: str
    api_version: str
    api_style: str = "v1"
    use_agent_service: bool
    api_key_set: bool
    mock_mode: bool
    auth_mode: str
    kind: str = "cloud"              # mock | local | cloud
    context_tokens: int | None = None
    concurrency: int | None = None
    roles: ModelRolesOut = ModelRolesOut()
    active_profile_id: str | None = None
    active_profile_name: str | None = None


class FoundrySettingsUpdate(BaseModel):
    endpoint: str | None = None
    api_key: str | None = None       # blank => leave existing secret unchanged
    deployment: str | None = None
    api_version: str | None = None
    api_style: str | None = None     # v1 | azure | local
    use_agent_service: bool | None = None
    roles: ModelRolesOut | None = None
    context_tokens: int | None = None  # null/0 => auto-detect from model name
    concurrency: int | None = None     # null/0 => global default


# ---- AI profiles (saved connection + roles + tuning) ----
class AiProfileOut(FoundrySettingsOut):
    id: str
    name: str
    description: str | None = None
    active: bool = False


class AiProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    # true: snapshot the active config (incl. its API key, server-side);
    # false: start from `settings` only (e.g. a local/cloud template).
    from_current: bool = True
    settings: FoundrySettingsUpdate | None = None
    activate: bool = False


class AiProfileUpdate(FoundrySettingsUpdate):
    name: str | None = Field(default=None, max_length=120)
    description: str | None = None


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


# ---- DAST (live access-control confirmation) ----
class DastCredentialIn(BaseModel):
    role_label: str = Field(max_length=60)
    auth_kind: str = "bearer"                 # bearer | cookie | header | login_form
    header_name: str | None = None
    secret: str | None = None                 # write-only; blank keeps existing
    is_privileged: bool = False


class DastCredentialOut(BaseModel):
    id: str
    role_label: str
    auth_kind: str
    header_name: str | None = None
    is_privileged: bool = False
    secret_set: bool = False


class DastTargetIn(BaseModel):
    label: str | None = None
    base_url: str
    allowed_hosts: list[str] | None = None
    active_scan_enabled: bool = False
    burp_mcp_id: str | None = None
    object_seeds: dict = Field(default_factory=dict)
    max_rps: float | None = None


class DastTargetUpdate(BaseModel):
    label: str | None = None
    base_url: str | None = None
    allowed_hosts: list[str] | None = None
    active_scan_enabled: bool | None = None
    burp_mcp_id: str | None = None
    object_seeds: dict | None = None
    max_rps: float | None = None
    enabled: bool | None = None
    mode_config: dict | None = None


class DastTargetOut(BaseModel):
    id: str
    project_id: str
    label: str
    base_url: str
    allowed_hosts: list[str] = Field(default_factory=list)
    active_scan_enabled: bool = False
    burp_mcp_id: str | None = None
    max_rps: float = 5.0
    enabled: bool = True
    object_seeds: dict = Field(default_factory=dict)
    mode_config: dict = Field(default_factory=dict)
    secrets_available: bool = False
    credentials: list[DastCredentialOut] = Field(default_factory=list)


class DastRunCreate(BaseModel):
    target_id: str
    # Explicit authorization: the operator attests they may test this host.
    authorize: bool = False
    allow_mutating: bool = False
    access_control: bool = True          # confirm access-control findings
    active_scan: bool = False            # native active checks (+ Burp if attached)
    include_paths: list[str] | None = None   # only test paths starting with these
    exclude_paths: list[str] | None = None   # never test paths starting with these
    intercept: str = "off"                    # off | mutating | all — hold before requests


class DastControlPatch(BaseModel):
    """Live edits to an in-flight run. Tighten-only: the server ignores any
    attempt to loosen (raise rate above launch, re-enable mutating)."""
    status: str | None = None                 # running | paused | canceled
    max_rps: float | None = None              # lowered on the fly (<= launch rate)
    allow_mutating: bool | None = None        # only False is honoured (turn off)
    exclude_paths: list[str] | None = None    # additive path-prefix skips
    intercept: str | None = None              # off | mutating | all


class DastInterceptDecision(BaseModel):
    verdict: str                              # allow | skip | allow_rest | skip_rest


class DastPlanRequest(BaseModel):
    target_id: str
    access_control: bool = True
    active_scan: bool = False
    include_paths: list[str] | None = None
    exclude_paths: list[str] | None = None


class DastRunOut(ORMModel):
    scan_id: str
    target_id: str
    status: str
    authorized_by: str | None = None
    authorized_at: datetime | None = None
    allow_mutating: bool = False
    config: dict = {}
    summary: dict = {}
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


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
    method: str = "ANY"
    path: str = "/"
    file_path: str = ""
    line: int = 0
    framework: str = ""
    handler: str | None = None
    auth_hints: list[str] = Field(default_factory=list)
    # Access-control enrichment / AI verdicts (present when that check ran).
    auth_scope: str | None = None     # route | file | global | public | none
    state_changing: bool | None = None
    sensitive: bool | None = None
    heuristic_risk: str | None = None
    authn: str | None = None          # required | none | public | unclear | unassessed
    authz: str | None = None          # role | ownership | tenant | none | unclear
    risk: str | None = None
    notes: str | None = None


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
