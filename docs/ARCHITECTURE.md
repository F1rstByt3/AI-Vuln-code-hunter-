# Architecture & flow

## Components

```
                         ┌──────────────────────────────────────────┐
 Browser (React/TS) ───► │  FastAPI API  (clients/projects/scans/…)   │
   live SSE  ◄────────── │  + SSE stream  + runtime settings          │
                         └───────┬───────────────────────┬───────────┘
                                 │ enqueue               │ read/write
                                 ▼                       ▼
                         ┌───────────────┐        ┌──────────────┐
                         │  Redis (arq)  │        │  Postgres     │
                         │  queue+events │        │  domain data  │
                         └───────┬───────┘        └──────────────┘
                                 │ job
                                 ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  Worker:  ingest ─► static scan ─► agentic AI review ─► persist     │
   │           │            │                  │                         │
   │           ▼            ▼                  ▼                         │
   │   Object storage   Semgrep / MCP    Azure AI Foundry               │
   │   (Blob / MinIO)   (SonarQube…)     (GPT-Codex)  + mock fallback    │
   └──────────────────────────────────────────────────────────────────┘
```

## Data model

`Client → Project → Artifact → Scan → Finding`, plus:
- **ArtifactFile** — indexed analyzable surface per snapshot.
- **McpServer** — registered MCP tools (workspace- or project-scoped).
- **ChatMessage** — interactive Q&A per scan.
- **AgentEvent** — append-only, replayable log of streamed output.
- **Setting** — runtime config (Foundry endpoint/key/model) layered over `.env`.

Finding state machine: `proposed → confirmed | dismissed | needs_info`. Triage
decisions persist and are intended to feed back into later scans.

## Why SAST-first, LLM-second

Feeding 10GB to a model is impossible and pointless. Instead:
- **Recall** comes from static tools across the *entire* tree (cheap, fast).
- **Precision + reasoning + logic flaws** come from the LLM, applied only to
  candidates and targeted code windows it retrieves on demand.
- Result: bounded token cost/latency **independent of repo size**, and far fewer
  hallucinations because every finding must cite `file:line` + quoted code.

## Multi-model pipeline (roles + ensemble + judge)

The AI stage is split into roles, each mapped to its own Foundry deployment
(editable in **Settings → Model roles**, or via `FOUNDRY_*_MODEL` env vars):

| Role | Job | Typical model |
|------|-----|---------------|
| **chat** | Live plan narration + interactive Q&A | gpt-4o / gpt-5 |
| **reviewer(s)** | Deep vuln hunting on candidates + code windows | gpt-5-codex, gpt-5 |
| **judge** | Validates each finding vs. evidence, dedupes, sets final state | o4-mini / gpt-5 |

Flow: SAST candidates → **N reviewers run concurrently** (each finding tagged with
its `reviewed_by` model) → **judge** consolidates: merges duplicates, `confirm`s
evidence-backed issues, `dismiss`es unsupported ones, routes business-logic calls to
`needs_info`. Adding reviewers raises recall; the judge keeps precision high.

**Transport.** Codex and o-series models are *Responses-API only* and reject Chat
Completions; conversational models use Chat Completions. Each role's transport is
`auto` (inferred from the model name) by default, overridable to `chat`/`responses`.
All roles share one Foundry v1 client (`<endpoint>/openai/v1/`).

Reviewers and the judge degrade gracefully: a single reviewer erroring is logged and
skipped; if the judge call fails the raw reviewer findings are kept.

## Large-file handling (10GB+)

- **Upload**: resumable multipart (`init → PUT parts → complete`) straight to
  object storage; a giant file survives network blips and never sits in API RAM.
  In prod, prefer **direct-to-Blob SAS** to bypass the API entirely.
- **Extraction**: streamed, with zip-bomb guards (max files, max extracted bytes)
  and path-traversal blocking.
- **Indexing**: binaries (null-byte sniff), vendored dirs, and oversized files are
  excluded from the *AI* surface (static tools still see them).

## Human-in-the-loop

The agent emits `needs_info` findings carrying a **specific question** whenever
exploitability depends on business logic it can't infer. These surface in the
dashboard's review queue and in the scan's chat, where you answer inline.

## Flow improvements on the roadmap

- [ ] **Incremental/diff scans** — after the first full scan, only re-analyze
      `git diff` to cut re-run cost.
- [ ] **Retrieval/RAG over code** (pgvector / Azure AI Search) so the agent pulls
      relevant chunks instead of being handed file lists — sharper on huge repos.
- [ ] **Foundry Agent Service + tool-calling**: let the model call MCP tools
      (Semgrep, AST, file-read) directly within an agent run (`FOUNDRY_USE_AGENT_SERVICE`).
- [ ] **Feedback loop**: feed persisted FP/TP triage back as context to suppress
      repeat noise.
- [ ] **Model routing**: cheap deployment for triage, Codex/strong for deep dives
      (`AI_TRIAGE_MODEL`).
- [ ] **Dependency/secret scanning** (Trivy/Grype, gitleaks) as additional MCP tools.
- [ ] **Alembic migrations** replacing dev `create_all`.
- [ ] **MSAL** in the SPA + per-client RBAC enforcement.
- [ ] **Reporting**: export findings (SARIF, PDF) per scan/engagement.

## Extending scanners

Implement the `Scanner` protocol (`backend/app/scanners/base.py`) or register an
MCP server in **Settings** that exposes a `scan` tool returning findings — both
fold into the same `Candidate` shape the agent triages.
