"""Azure AI Foundry client.

Two interchangeable implementations behind one interface:
  * AzureFoundryClient  — real inference via the Azure OpenAI-compatible endpoint
                          (API key OR service-principal / managed-identity auth).
  * MockFoundryClient   — deterministic, offline. Lets the entire review flow run
                          (and stream) with zero Azure setup, so you can demo first.

Connection settings come from a FoundryConfig, which the app builds at runtime by
layering the in-app Settings (DB) over .env defaults — so the endpoint, API key and
model can be changed from the UI without a redeploy. No endpoint => mock mode.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass

from app.config import settings

log = logging.getLogger(__name__)

_CTX_RE = re.compile(r"<<CONTEXT_JSON>>(.*?)<<END>>", re.DOTALL)


@dataclass
class FoundryConfig:
    """Effective connection config for one inference call."""

    endpoint: str | None = None
    api_key: str | None = None
    deployment: str = "gpt-codex"
    api_version: str = "2025-04-01-preview"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    use_agent_service: bool = False

    @property
    def mock(self) -> bool:
        return not self.endpoint

    @classmethod
    def from_settings(cls) -> FoundryConfig:
        return cls(
            endpoint=settings.foundry_endpoint,
            api_key=settings.foundry_api_key,
            deployment=settings.foundry_deployment,
            api_version=settings.foundry_api_version,
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
            use_agent_service=settings.foundry_use_agent_service,
        )


class FoundryClient(ABC):
    @abstractmethod
    async def chat_stream(
        self, messages: list[dict], temperature: float = 0.2, model: str | None = None
    ) -> AsyncIterator[str]: ...

    @abstractmethod
    async def chat_json(
        self, messages: list[dict], temperature: float = 0.1, model: str | None = None
    ) -> dict: ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Deployments/models available from the configured Foundry project."""


class AzureFoundryClient(FoundryClient):
    def __init__(self, cfg: FoundryConfig) -> None:
        from openai import AsyncAzureOpenAI

        self.cfg = cfg
        kwargs: dict = dict(azure_endpoint=cfg.endpoint, api_version=cfg.api_version)
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key
        elif cfg.client_id and cfg.client_secret:
            from azure.identity import ClientSecretCredential, get_bearer_token_provider

            cred = ClientSecretCredential(cfg.tenant_id, cfg.client_id, cfg.client_secret)
            kwargs["azure_ad_token_provider"] = get_bearer_token_provider(
                cred, "https://cognitiveservices.azure.com/.default"
            )
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            kwargs["azure_ad_token_provider"] = get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            )
        self._client = AsyncAzureOpenAI(**kwargs)

    async def chat_stream(self, messages, temperature=0.2, model=None):
        deployment = model or self.cfg.deployment
        log.info("chat_stream: endpoint=%s deployment=%s api_version=%s",
                 self.cfg.endpoint, deployment, self.cfg.api_version)
        stream = await self._client.chat.completions.create(
            model=deployment,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices and (delta := chunk.choices[0].delta.content):
                yield delta

    async def chat_json(self, messages, temperature=0.1, model=None):
        resp = await self._client.chat.completions.create(
            model=model or self.cfg.deployment,
            messages=messages,
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        return json.loads(resp.choices[0].message.content or "{}")

    async def list_models(self) -> list[str]:
        try:
            resp = await self._client.models.list()
            return sorted({m.id for m in resp.data})
        except Exception:  # noqa: BLE001 — surface as "none discovered", let user type one
            return []


class MockFoundryClient(FoundryClient):
    """Offline reviewer. Narrates plausibly and turns static-tool candidates into
    structured findings, plus a canned business-logic item routed to a human —
    exercising the full pipeline without a model."""

    MODELS = ["gpt-codex", "gpt-4o", "gpt-4.1", "gpt-4.1-mini", "o4-mini"]

    async def chat_stream(self, messages, temperature=0.2, model=None):
        text = (
            "[MOCK reviewer] Planning the review. I'll triage the static-analysis "
            "candidates first, then hunt for logic flaws the scanners miss "
            "(authz, IDOR, unsafe deserialization, secret handling).\n"
        )
        for token in re.findall(r"\S+\s*", text):
            yield token
            await asyncio.sleep(0.005)

    async def chat_json(self, messages, temperature=0.1, model=None):
        ctx = self._extract_ctx(messages)
        findings: list[dict] = []
        for c in ctx.get("candidates", []):
            findings.append(
                {
                    "title": c.get("title") or c.get("rule") or "Static-analysis candidate",
                    "description": (
                        f"Confirmed candidate from {c.get('source', 'semgrep')}: "
                        f"{c.get('message', '')}".strip()
                    ),
                    "severity": c.get("severity", "medium"),
                    "confidence": 0.7,
                    "cwe": c.get("cwe"),
                    "owasp": c.get("owasp"),
                    "category": c.get("category") or "static-analysis",
                    "file_path": c.get("file_path"),
                    "line_start": c.get("line_start"),
                    "line_end": c.get("line_end"),
                    "code_snippet": c.get("code_snippet"),
                    "remediation": "Validate/parameterise inputs; see referenced rule.",
                    "source": "correlated",
                    "state": "proposed",
                }
            )
        first_file = (ctx.get("files") or [{}])[0].get("path")
        findings.append(
            {
                "title": "Possible broken access control on object lookup",
                "description": (
                    "Object is fetched by client-supplied id without an ownership check. "
                    "Whether this is exploitable depends on business rules I can't infer."
                ),
                "severity": "high",
                "confidence": 0.4,
                "cwe": "CWE-639",
                "owasp": "A01:2021",
                "category": "access-control",
                "file_path": first_file,
                "line_start": 1,
                "line_end": 1,
                "code_snippet": None,
                "remediation": "Enforce per-object authorization tied to the session principal.",
                "source": "ai",
                "state": "needs_info",
                "human_question": (
                    "Should this endpoint be restricted to the resource owner? "
                    "Confirm the intended authorization rule."
                ),
            }
        )
        return {"findings": findings}

    async def list_models(self) -> list[str]:
        return list(self.MODELS)

    @staticmethod
    def _extract_ctx(messages: list[dict]) -> dict:
        for m in reversed(messages):
            match = _CTX_RE.search(m.get("content", "") or "")
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    return {}
        return {}


def get_foundry_client(cfg: FoundryConfig | None = None) -> FoundryClient:
    cfg = cfg or FoundryConfig.from_settings()
    return MockFoundryClient() if cfg.mock else AzureFoundryClient(cfg)
