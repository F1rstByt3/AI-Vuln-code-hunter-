"""AI inference client — supports Azure AI Foundry, local models, and mock.

Three implementations behind one interface:
  * AzureFoundryClient  — real inference via the Azure AI Foundry v1 API or
                          any OpenAI-compatible endpoint (Ollama, vLLM, LM
                          Studio, llama.cpp, etc.). Auto-detects local vs
                          Azure from the endpoint URL.
  * MockFoundryClient   — deterministic, offline. Lets the entire review flow
                          run (and stream) with zero setup, so you can demo.

Connection settings come from a FoundryConfig, which the app builds at runtime
by layering the in-app Settings (DB) over .env defaults — so the endpoint, API
key and models can be changed from the UI without a redeploy.

  No endpoint             => mock mode
  localhost / 127.0.0.1   => local mode (Ollama, vLLM, etc.)
  *.openai.azure.com      => Azure AI Foundry

Transport: some Azure models (gpt-5-codex, o-series) are *Responses API only*
and reject Chat Completions. We auto-detect from the model name unless a role
pins it explicitly. Local models always use Chat Completions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.config import settings

log = logging.getLogger(__name__)

_CTX_RE = re.compile(r"<<CONTEXT_JSON>>(.*?)<<END>>", re.DOTALL)
_FINDINGS_RE = re.compile(r"<<FINDINGS_JSON>>(.*?)<<END>>", re.DOTALL)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

# Models that only speak the Responses API (no Chat Completions).
_RESPONSES_HINTS = ("codex", "o1", "o1-", "o3", "o3-", "o4", "o4-", "-reasoning")

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"}


def _is_local_endpoint(endpoint: str | None) -> bool:
    if not endpoint:
        return False
    try:
        host = urlparse(endpoint).hostname or ""
        return host in _LOCAL_HOSTS or host.startswith("192.168.") or host.startswith("10.")
    except Exception:
        return False


def _auto_transport(model: str | None, local: bool = False) -> str:
    if local:
        return "chat"
    m = (model or "").lower()
    if any(h in m for h in _RESPONSES_HINTS) or m.startswith(("o1", "o3", "o4")):
        return "responses"
    return "chat"


def _is_reasoning(model: str | None) -> bool:
    m = (model or "").lower()
    return "codex" in m or m.startswith(("o1", "o3", "o4")) or "gpt-5" in m


@dataclass
class ModelRole:
    """One model assignment: which deployment, how to call it, how hard to think."""

    deployment: str
    transport: str = "auto"           # auto | chat | responses
    reasoning_effort: str | None = None  # low | medium | high (reasoning/codex only)

    def effective_transport(self, local: bool = False) -> str:
        t = (self.transport or "auto").lower()
        return _auto_transport(self.deployment, local=local) if t == "auto" else t

    @classmethod
    def parse(cls, data) -> ModelRole | None:
        if not data:
            return None
        if isinstance(data, str):
            return cls(deployment=data)
        if isinstance(data, dict) and data.get("deployment"):
            return cls(
                deployment=str(data["deployment"]),
                transport=str(data.get("transport", "auto")),
                reasoning_effort=data.get("reasoning_effort"),
            )
        return None

    def to_dict(self) -> dict:
        return {
            "deployment": self.deployment,
            "transport": self.transport,
            "reasoning_effort": self.reasoning_effort,
        }


@dataclass
class ReviewRoles:
    """Resolved model assignments for one scan."""

    chat: ModelRole
    reviewers: list[ModelRole]
    judge: ModelRole | None


@dataclass
class FoundryConfig:
    """Effective connection config + model-role assignments."""

    endpoint: str | None = None
    api_key: str | None = None
    deployment: str = "gpt-codex"     # the default/fallback model
    api_version: str = "preview"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    use_agent_service: bool = False
    # "v1" = new Foundry Models v1 API (OpenAI client, base_url .../openai/v1/);
    # "azure" = legacy AzureOpenAI (/openai/deployments/{dep}/...?api-version=);
    # "local" = OpenAI-compatible local server (Ollama, vLLM, LM Studio).
    api_style: str = "v1"
    # Multi-model roles (all optional; fall back to `deployment`).
    chat_model: ModelRole | None = None
    reviewer_models: list[ModelRole] = field(default_factory=list)
    judge_model: ModelRole | None = None

    @property
    def mock(self) -> bool:
        return not self.endpoint

    @property
    def is_local(self) -> bool:
        return (self.api_style or "").lower() == "local" or _is_local_endpoint(self.endpoint)

    def resolve_roles(self, reviewer_override: str | None = None) -> ReviewRoles:
        fallback = ModelRole(deployment=self.deployment)
        chat = self.chat_model or fallback
        if reviewer_override:
            reviewers = [ModelRole(deployment=reviewer_override)]
        else:
            reviewers = list(self.reviewer_models) or [fallback]
        judge = self.judge_model
        return ReviewRoles(chat=chat, reviewers=reviewers, judge=judge)

    @classmethod
    def from_settings(cls) -> FoundryConfig:
        reviewers = [
            ModelRole(deployment=d.strip())
            for d in (settings.foundry_reviewer_models or "").split(",")
            if d.strip()
        ]
        return cls(
            endpoint=settings.foundry_endpoint,
            api_key=settings.foundry_api_key,
            deployment=settings.foundry_deployment,
            api_version=settings.foundry_api_version,
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
            use_agent_service=settings.foundry_use_agent_service,
            api_style=settings.foundry_api_style,
            chat_model=ModelRole.parse(settings.foundry_chat_model),
            reviewer_models=reviewers,
            judge_model=ModelRole.parse(settings.foundry_judge_model),
        )


class FoundryClient(ABC):
    """Transport-aware inference. `transport` is auto | chat | responses."""

    @abstractmethod
    def stream(
        self, messages: list[dict], *, model: str | None = None, transport: str = "auto",
        temperature: float = 0.2, reasoning_effort: str | None = None,
    ) -> AsyncIterator[str]: ...

    @abstractmethod
    async def complete_json(
        self, messages: list[dict], *, model: str | None = None, transport: str = "auto",
        temperature: float = 0.1, reasoning_effort: str | None = None,
    ) -> dict: ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Deployments/models available from the configured project/server."""

    def chat_stream(self, messages, temperature: float = 0.2, model: str | None = None):
        return self.stream(messages, model=model, transport="chat", temperature=temperature)

    async def chat_json(self, messages, temperature: float = 0.1, model: str | None = None):
        return await self.complete_json(
            messages, model=model, transport="chat", temperature=temperature
        )


def _entra_token(cfg: FoundryConfig, scope: str) -> str:
    if cfg.client_id and cfg.client_secret:
        from azure.identity import ClientSecretCredential

        cred = ClientSecretCredential(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    else:
        from azure.identity import DefaultAzureCredential

        cred = DefaultAzureCredential()
    return cred.get_token(scope).token


def _resolve_base_url(endpoint: str, api_style: str) -> str:
    """Build the OpenAI client base_url from the user-provided endpoint.

    Local servers (Ollama, vLLM, LM Studio) use /v1 directly.
    Azure Foundry v1 API uses /openai/v1/.
    If the URL already ends with /v1, use it as-is.
    """
    base = endpoint.rstrip("/")
    lower = base.lower()
    if lower.endswith("/v1") or lower.endswith("/openai/v1"):
        return base + "/"
    style = (api_style or "v1").lower()
    if style == "local" or _is_local_endpoint(endpoint):
        return base + "/v1/"
    return base + "/openai/v1/"


def _split_messages(messages: list[dict]) -> tuple[str, list[dict]]:
    """Responses API takes system text as `instructions` and the rest as `input`."""
    instructions = "\n\n".join(
        str(m.get("content", "")) for m in messages if m.get("role") == "system"
    )
    inp = [
        {"role": m["role"], "content": str(m.get("content", ""))}
        for m in messages
        if m.get("role") != "system"
    ]
    return instructions, inp


def _parse_json(text: str | None) -> dict:
    if not text:
        return {}
    text = text.strip()
    fence = _JSON_FENCE_RE.search(text)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return {}
        return {}


class InferenceClient(FoundryClient):
    """Connects to Azure AI Foundry OR any OpenAI-compatible server (Ollama,
    vLLM, LM Studio, llama.cpp, text-generation-inference, etc.).

    Auto-detects local vs Azure from the endpoint URL and adjusts behaviour:
    - Local: always Chat Completions, no api-version, json_object mode optional
    - Azure v1: /openai/v1/ base, Responses API for codex/o-series
    - Azure legacy: AzureOpenAI client with api-version query param
    """

    def __init__(self, cfg: FoundryConfig) -> None:
        self.cfg = cfg
        self._local = cfg.is_local
        self._azure_style = (cfg.api_style or "v1").lower() == "azure" and not self._local
        if self._azure_style:
            self._client = self._build_azure(cfg)
        else:
            self._client = self._build_openai(cfg)

    @staticmethod
    def _build_openai(cfg: FoundryConfig):
        from openai import AsyncOpenAI

        base_url = _resolve_base_url(cfg.endpoint or "", cfg.api_style or "v1")
        local = cfg.is_local

        # API version: local servers don't need it; Azure v1 uses "preview"
        ver = (cfg.api_version or "").strip() if not local else ""
        if ver and re.match(r"^\d{4}-\d{2}-\d{2}", ver):
            ver = "preview"
        default_query = {"api-version": ver} if ver else None

        if cfg.api_key:
            api_key = cfg.api_key
        elif local:
            api_key = "not-needed"
        else:
            api_key = _entra_token(cfg, scope="https://ai.azure.com/.default")

        return AsyncOpenAI(base_url=base_url, api_key=api_key, default_query=default_query)

    @staticmethod
    def _build_azure(cfg: FoundryConfig):
        from openai import AsyncAzureOpenAI

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
        return AsyncAzureOpenAI(**kwargs)

    def _transport_for(self, model: str | None, transport: str) -> str:
        t = (transport or "auto").lower()
        return _auto_transport(model or self.cfg.deployment, local=self._local) if t == "auto" else t

    async def stream(self, messages, *, model=None, transport="auto",
                     temperature=0.2, reasoning_effort=None):
        deployment = model or self.cfg.deployment
        t = self._transport_for(deployment, transport)
        log.info("stream: base_url=%s local=%s deployment=%s transport=%s",
                 str(self._client.base_url), self._local, deployment, t)
        if t == "responses" and not self._local:
            async for tok in self._responses_stream(messages, deployment, reasoning_effort):
                yield tok
        else:
            stream = await self._client.chat.completions.create(
                model=deployment, messages=messages, temperature=temperature, stream=True,
            )
            async for chunk in stream:
                if chunk.choices and (delta := chunk.choices[0].delta.content):
                    yield delta

    async def complete_json(self, messages, *, model=None, transport="auto",
                            temperature=0.1, reasoning_effort=None):
        deployment = model or self.cfg.deployment
        t = self._transport_for(deployment, transport)
        log.info("complete_json: deployment=%s transport=%s local=%s", deployment, t, self._local)

        if t == "responses" and not self._local:
            instructions, inp = _split_messages(messages)
            kwargs: dict = dict(model=deployment, input=inp)
            if instructions:
                kwargs["instructions"] = instructions
            if reasoning_effort and _is_reasoning(deployment):
                kwargs["reasoning"] = {"effort": reasoning_effort}
            resp = await self._client.responses.create(**kwargs)
            return _parse_json(getattr(resp, "output_text", None))

        # Chat Completions — try json_object mode, fall back to plain if unsupported
        try:
            resp = await self._client.chat.completions.create(
                model=deployment, messages=messages, temperature=temperature,
                response_format={"type": "json_object"},
            )
            return _parse_json(resp.choices[0].message.content)
        except Exception as e:
            if self._local and "json" in str(e).lower():
                # Model doesn't support json_object mode; retry without it
                log.warning("json_object mode unsupported by %s, retrying plain", deployment)
                resp = await self._client.chat.completions.create(
                    model=deployment, messages=messages, temperature=temperature,
                )
                return _parse_json(resp.choices[0].message.content)
            raise

    async def _responses_stream(self, messages, deployment, reasoning_effort):
        instructions, inp = _split_messages(messages)
        kwargs: dict = dict(model=deployment, input=inp, stream=True)
        if instructions:
            kwargs["instructions"] = instructions
        if reasoning_effort and _is_reasoning(deployment):
            kwargs["reasoning"] = {"effort": reasoning_effort}
        stream = await self._client.responses.create(**kwargs)
        async for event in stream:
            etype = getattr(event, "type", "")
            if etype == "response.output_text.delta":
                yield getattr(event, "delta", "")

    async def list_models(self) -> list[str]:
        try:
            resp = await self._client.models.list()
            return sorted({m.id for m in resp.data})
        except Exception:  # noqa: BLE001
            return []


# Keep backward compat name
AzureFoundryClient = InferenceClient


class MockFoundryClient(FoundryClient):
    """Offline reviewer + judge. Exercises the full pipeline with zero setup."""

    MODELS = ["gpt-5-codex", "gpt-5", "gpt-4o", "gpt-4.1", "o4-mini",
              "llama3.1:70b", "qwen2.5-coder:32b", "deepseek-coder-v2"]

    async def stream(self, messages, *, model=None, transport="auto",
                     temperature=0.2, reasoning_effort=None):
        text = (
            f"[MOCK {model or 'reviewer'}] Planning the review. I'll triage the "
            "static-analysis candidates first, then hunt for logic flaws the scanners "
            "miss (authz, IDOR, unsafe deserialization, secret handling).\n"
        )
        for token in re.findall(r"\S+\s*", text):
            yield token
            await asyncio.sleep(0.005)

    async def complete_json(self, messages, *, model=None, transport="auto",
                            temperature=0.1, reasoning_effort=None):
        judged = self._extract(messages, _FINDINGS_RE)
        if judged is not None:
            return {"findings": self._judge(judged.get("findings", []))}
        return {"findings": self._review(self._extract(messages, _CTX_RE) or {})}

    def _review(self, ctx: dict) -> list[dict]:
        findings: list[dict] = []
        for c in (ctx.get("static_analysis_results") or ctx.get("candidates") or []):
            findings.append({
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
            })
        source_files = ctx.get("source_files") or []
        first_file = (source_files[0].get("path") if source_files
                       else None)
        findings.append({
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
        })
        return findings

    def _judge(self, findings: list[dict]) -> list[dict]:
        seen: dict[tuple, dict] = {}
        out: list[dict] = []
        for f in findings:
            key = (f.get("title"), f.get("file_path"))
            if key in seen:
                seen[key].setdefault("raw", {}).setdefault("merged_count", 1)
                seen[key]["raw"]["merged_count"] += 1
                continue
            verdict = dict(f)
            if f.get("state") == "needs_info":
                pass
            elif f.get("file_path"):
                verdict["state"] = "confirmed"
                verdict["confidence"] = max(float(f.get("confidence", 0.5)), 0.75)
                verdict["triage_note"] = "Judge: evidence present (file:line); confirmed."
            else:
                verdict["state"] = "dismissed"
                verdict["triage_note"] = "Judge: no file:line evidence; likely false positive."
            verdict["triaged_by"] = "judge:mock"
            seen[key] = verdict
            out.append(verdict)
        return out

    async def list_models(self) -> list[str]:
        return list(self.MODELS)

    @staticmethod
    def _extract(messages: list[dict], pattern: re.Pattern) -> dict | None:
        for m in reversed(messages):
            match = pattern.search(m.get("content", "") or "")
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    return {}
        return None


def get_foundry_client(cfg: FoundryConfig | None = None) -> FoundryClient:
    cfg = cfg or FoundryConfig.from_settings()
    if cfg.mock:
        return MockFoundryClient()
    return InferenceClient(cfg)
