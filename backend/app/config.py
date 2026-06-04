"""Central configuration. All knobs come from env (see .env.example)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # ---- Core ----
    environment: str = "dev"
    log_level: str = "INFO"
    api_base_url: str = "http://localhost:8000"

    # ---- Infra ----
    database_url: str = "postgresql+asyncpg://hunter:hunter@db:5432/hunter"
    redis_url: str = "redis://redis:6379/0"

    # ---- Object storage ----
    storage_backend: str = "s3"  # s3 | azure_blob
    s3_endpoint_url: str | None = "http://minio:9000"
    s3_access_key: str = "hunter"
    s3_secret_key: str = "hunter-secret"
    s3_bucket: str = "hunter-artifacts"
    s3_region: str = "us-east-1"
    azure_storage_account: str | None = None
    azure_storage_container: str = "hunter-artifacts"
    azure_storage_connection_string: str | None = None

    # ---- Azure AI Foundry ----
    foundry_endpoint: str | None = None  # blank => mock mode
    foundry_deployment: str = "gpt-codex"
    foundry_api_version: str = "preview"
    foundry_api_style: str = "v1"  # v1 (Foundry Models v1 API) | azure (legacy)
    # ---- Multi-model roles (optional; default to FOUNDRY_DEPLOYMENT) ----
    # Reviewers can be a comma-separated list to run an ensemble.
    foundry_chat_model: str | None = None
    foundry_reviewer_models: str | None = None
    foundry_judge_model: str | None = None
    foundry_exploit_model: str | None = None  # writes PoC / risk / recommendation
    foundry_api_key: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    foundry_use_agent_service: bool = False

    # ---- Auth (Entra ID) ----
    auth_disabled: bool = True
    entra_tenant_id: str | None = None
    entra_client_id: str | None = None
    entra_audience: str | None = None

    # ---- Scanners ----
    semgrep_enabled: bool = True
    semgrep_ruleset: str = "auto"
    sonarqube_enabled: bool = False
    sonarqube_url: str | None = None
    sonarqube_token: str | None = None

    # ---- Ingestion limits ----
    max_upload_bytes: int = 10_995_116_277_760
    max_extract_bytes: int = 53_687_091_200
    max_extract_files: int = 2_000_000
    max_file_bytes_for_ai: int = 1_048_576
    upload_chunk_bytes: int = 8_388_608

    # ---- AI controls ----
    ai_max_findings_per_scan: int = 500
    ai_batch_tokens: int = 150_000  # auto-sized from model ctx when 80K or 150K
    ai_batch_concurrency: int = 4   # batches per reviewer processed in parallel
    ai_triage_model: str | None = None
    ai_require_evidence: bool = True
    # Only write exploit PoCs for findings at/above this severity (the exploit
    # phase is expensive). critical | high | medium | low | info.
    ai_exploit_min_severity: str = "high"

    @property
    def foundry_mock(self) -> bool:
        """No endpoint configured => run the agent against the deterministic mock."""
        return not self.foundry_endpoint


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
