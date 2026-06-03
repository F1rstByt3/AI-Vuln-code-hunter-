# 🛡️ AI Vuln Code Hunter

Agentic, AI-assisted **code-security review** platform. Point it at a codebase and
an LLM reviewer (your **Azure AI Foundry** deployment, e.g. GPT‑Codex) triages
static-analysis findings, hunts for logic flaws the scanners miss, and routes
anything it can't decide — business-logic questions — to a human queue. Results
stream live and land in a per-project vulnerability dashboard.

> **Design principle: SAST-first, LLM-second.** Fast static tools (Semgrep,
> SonarQube via MCP) do the broad, high-recall sweep over the whole tree; the LLM
> does deep reasoning only on candidates + targeted samples. Token cost and
> latency stay bounded **regardless of repo size** — that's how 10GB+ inputs work.

```
Client → Project → Artifact (code snapshot) → Scan → Findings
```

## What's here

| Area | Status |
|---|---|
| FastAPI backend, full data model, 26 REST routes | ✅ verified (boots, smoke-tested on SQLite) |
| Agentic review loop + Azure Foundry client (+ **mock mode**) | ✅ runs end-to-end with **zero Azure** |
| Ingestion: resumable 10GB+ upload, safe archive extraction, file indexing | ✅ |
| Semgrep adapter + MCP client (Semgrep/SonarQube/custom) | ✅ |
| arq worker: ingest → static scan → AI review, live SSE | ✅ |
| React/TS UI: clients/projects, live scan view, triage, chat, dashboard, settings | ✅ prod build passes |
| Entra ID auth (+ dev bypass), runtime-editable Foundry settings, model picker | ✅ |
| Azure infra (Bicep, all fresh except Foundry) | ✅ starting point |

## Quickstart (local, no Azure needed)

```bash
cp .env.example .env          # defaults run in mock + no-auth mode
docker compose up --build
```

- UI: http://localhost:5173 · API docs: http://localhost:8000/docs · MinIO: http://localhost:9001

With `FOUNDRY_ENDPOINT` blank, the reviewer runs in **deterministic mock mode** —
create a client → project → link a git repo or upload a file → **Run analysis** and
watch the full pipeline stream findings, including a human-review item. Then add your
Foundry endpoint/key in **Settings** and pick a model to use the real reviewer.

### Run the tests

```bash
cd backend && python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pytest -q          # agent pipeline runs without infra
```

## How a scan works

1. **Ingest** — materialize the artifact (download+extract upload / `git clone` /
   local mount), index the *analyzable surface* (skip binaries, vendored deps,
   oversized files). Guards against zip-bombs and path traversal.
2. **Static sweep** — Semgrep (and any enabled MCP scanners) over the whole tree →
   *candidates*.
3. **Agentic review** — the Foundry agent grounds each candidate in real code,
   confirms/denies with evidence (file:line), assigns severity + CWE/OWASP +
   remediation, and probes for logic flaws (authz, IDOR, races, secret handling).
   Uncertain / business-logic items become `needs_info` findings **with a specific
   question for you**.
4. **Live + interactive** — every step streams over SSE; you can chat with the
   reviewer during and after, and triage each finding
   (`confirmed` / `dismissed` / `needs_info`).
5. **Dashboard** — severity breakdown, risk score, CWE/OWASP categories, hotspot
   files, and the human-review queue.

## What you provide

- **Azure AI Foundry**: endpoint URL + the **model deployment name** + auth
  (API key, service principal, or managed identity). Set these in **Settings**
  (runtime, no redeploy) or `.env`. The model is selectable from those your
  Foundry project exposes.
- **Scanners** (optional): existing Semgrep/SonarQube MCP endpoints + tokens, or
  let the bundled Semgrep run.
- For production auth: an **Entra ID** app registration (see `infra/azure/README.md`).

## Security model (this tool reviews *untrusted* code)

- Uploaded code is **never executed** — only statically analyzed, in sandboxed,
  egress-restricted workers.
- File **contents are treated as untrusted data**, never as instructions
  (prompt-injection fencing in the agent).
- Findings without **file:line evidence can't be auto-confirmed** — cuts
  hallucinations on huge inputs.
- Secrets (Foundry key) are write-only via the API (returned masked); Key Vault in prod.

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the deep dive, flow
improvements, and roadmap.

## Repo layout

```
backend/    FastAPI app, agent, scanners, ingestion, worker, tests
frontend/   React + Vite + Tailwind SPA
infra/azure/ Bicep (Container Apps, Postgres, Blob, Redis, Key Vault, ACR)
docker-compose.yml  local dev stack
```
