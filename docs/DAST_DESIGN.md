# White-box SAST + DAST: live access-control confirmation & active scanning

Status: **design / proposal** (no code yet). Scope chosen with the team:
- Live testing depth: **access-control confirmation + safe active scan**.
- Credentials: **per-project, encrypted at rest**.
- Integration: **hybrid** — app-native request replay for access control, Burp
  (via MCP) for active scanning.

This document is the plan to review before implementation. It intentionally
front-loads the safety model, because this is the first feature that sends
traffic to a *running* target rather than only reading source.

---

## 1. Goal

Today the pipeline is white-box **SAST**: it reads source, finds candidate
vulnerabilities, and an access-control pass predicts which endpoints *should*
be protected (`app/scanners/access_control.py`). Those predictions are
heuristics + an AI verdict — informed guesses, not proof.

The goal is to **confirm** them against the live application, turning "possible
IDOR on `GET /users/{id}`" into "confirmed: user A read user B's object, HTTP
200, here is the request/response pair" — or dismissing it because the app
correctly returned 403. This is the precision win: static analysis says *where
to look*, dynamic testing says *whether it's real*.

Concretely:
1. **Access-control confirmation (BAC / IDOR / BFLA).** Replay each discovered
   endpoint with no auth, as a low-privilege user, and as another user, and
   compare. Drive each `access` finding to `confirmed` or `dismissed` with a
   captured request/response as evidence.
2. **Safe active scan.** Hand the discovered, authenticated request surface to
   Burp's active scanner for injection/XSS/etc. on the in-scope host, and
   ingest its findings back into the same findings list.

**This is authorized white-box testing of the operator's own systems.** Every
control below exists to keep it that way — scoped to targets the operator has
declared, gated on explicit per-run authorization, and never touching anything
outside the allow-list.

## 2. Non-goals

- Not a general-purpose scanner for arbitrary URLs. Runs are bound to a project
  and an operator-declared target.
- Not exploitation. Confirmation uses the minimum benign action to prove access
  (read an object that shouldn't be readable; observe a 200 where a 403 is
  expected). No data modification/exfiltration beyond what proves the finding;
  destructive HTTP methods are off by default (§7).
- Not credential harvesting or brute force. Credentials are *supplied by the
  operator* for *their own* test accounts.

---

## 3. Architecture

```
          ┌────────────── existing SAST pipeline ───────────────┐
 ingest → static scan → endpoints → access-control map → AI review → findings
          └──────────────────────────────────────────────────────┘
                                   │  (access findings + endpoint matrix)
                                   ▼
                    ┌──────────  NEW: DAST stage  ──────────┐
                    │  1. Correlate findings → live requests │
                    │  2. Access-control replay (app-native) │ ← test creds (roles)
                    │  3. Safe active scan (Burp via MCP)    │ ← in-scope host only
                    │  4. Ingest results, update findings    │
                    └────────────────────────────────────────┘
                                   │
                                   ▼
             findings become confirmed / dismissed, with live evidence
```

The DAST stage runs **only when** the operator has configured a target and
launches a run for it. A normal source-only scan is unchanged.

### 3.1 Why hybrid (app-native replay + Burp)

| Task | Who | Why |
|---|---|---|
| Access-control replay & response diffing | **App (httpx)** | Deterministic, fast, unit-testable, no external process, full control of the per-role comparison. This is the core precision logic. |
| Active scanning (injection, XSS, SSRF, …) | **Burp via MCP** | Purpose-built, maintained, far better than anything we'd reimplement. We already have an MCP client. |

We do **not** route the BAC replay through Burp: the comparison logic (status,
body similarity, length, per-role deltas) is the product's value and belongs in
code we test. Burp is the right tool for broad active scanning, which we would
never reimplement.

### 3.2 Burp connection (MCP)

Burp Suite 2025.x ships an official **MCP Server** extension. It exposes proxy
history, Repeater, Intruder and the active scanner over MCP. We already have
`app/scanners/mcp_client.py` and a per-project MCP server registry
(`McpServer` model, Settings UI), so Burp registers exactly like Semgrep/Sonar:

```
name: "burp"   kind: "burp"   transport: "sse"|"http"   url: http://host.docker.internal:9876
```

The worker connects to it during the active-scan step. If Burp is unreachable,
the active-scan step is skipped (logged), and access-control confirmation —
which needs no Burp — still runs. Requirements (Burp Pro for active scan, the
MCP extension enabled, the operator's own Burp instance) are documented, not
bundled.

---

## 4. Data model changes

New tables (created by `init_models()` like the rest, migrations auto-applied):

### `dast_targets`
One per project (or several — e.g. staging vs. local). Declares *what* may be
tested.
| column | notes |
|---|---|
| `id`, `project_id` | |
| `label` | "Staging", "Local dev" |
| `base_url` | the one host runs are scoped to |
| `allowed_hosts` | JSON list; requests outside → dropped (§7). Defaults to `base_url`'s host |
| `active_scan_enabled` | bool; gates the Burp step for this target |
| `burp_mcp_id` | FK to `McpServer` (nullable; access-control replay needs no Burp) |
| `max_rps` | client-side rate limit (default low, e.g. 5) |
| `enabled` | |

### `dast_credentials`
Test accounts, one per role. **Secrets encrypted at rest** (§6).
| column | notes |
|---|---|
| `id`, `target_id` | |
| `role_label` | "userA", "userB", "admin" |
| `auth_kind` | `bearer` \| `cookie` \| `header` \| `login_form` |
| `secret_enc` | encrypted blob: token / cookie jar / header value / login steps |
| `is_privileged` | marks the high-priv role for BFLA comparisons |

### `dast_runs`
One live-testing run against a target.
| column | notes |
|---|---|
| `id`, `scan_id`, `target_id` | a run is tied to the source scan it confirms |
| `status`, `authorized_by`, `authorized_at` | see §6 authorization gate |
| `summary` | counts: confirmed / dismissed / errored, active-scan issues |
| `started_at`, `finished_at` | |

### Findings
Reuse the existing `Finding` table. New `raw` fields on confirmed/updated items:
- `dast.verdict`: `confirmed_vuln` \| `enforced` (app correctly blocked) \|
  `inconclusive`.
- `dast.evidence`: sanitized request line + response status/length **per role**
  (no secrets, no full bodies by default — see §6).
- `dast.tested_at`, `dast.by` (`"access-replay"` or `"burp"`).
- Active-scan issues arrive as new findings with `source="ai"`? No — add a
  `FindingSource.dast` enum value (auto-migrated, as `access` was) so they tab
  separately in the UI.

---

## 5. The access-control confirmation loop (app-native)

Input: the scan's endpoint matrix + `access` findings. For each testable
endpoint:

1. **Build the base request** from the endpoint (method, path). Fill path
   params with values owned by the *primary* role (see object-seeding below).
2. **Send it under several identities**, each a `dast_credentials` role plus a
   no-auth baseline:
   - `none` (no creds)
   - `userA` (low-priv)
   - `userB` (different low-priv user — for cross-user object access)
   - `admin` (if present — establishes the "authorized" baseline)
3. **Compare** status codes, body similarity and length across identities.
4. **Decide** per finding class:

| Finding | Confirmed when… | Enforced (dismiss) when… |
|---|---|---|
| Missing authn (CWE-306) | `none` gets 2xx on a non-public, state-changing route | `none` gets 401/403 |
| IDOR / BOLA (CWE-639) | `userA` successfully reads/acts on `userB`'s object id | A gets 403/404 for B's object |
| BFLA / function authz (CWE-285) | low-priv role gets 2xx on a privileged route | low-priv gets 403 |
| Mass assignment (CWE-915) | a privileged field set in the body is reflected/persisted | field ignored/rejected |

**Object seeding.** IDOR testing needs a real object id owned by userB. Options,
in order of preference: (a) an operator-provided map of `{role: sample ids}` on
the target; (b) ids discovered by first calling list endpoints as each role and
harvesting ids from responses; (c) skip with `inconclusive` if neither is
available. This is captured as an explicit step so we never fabricate ids.

**Safety of the replay itself:** GET/HEAD/OPTIONS freely; POST/PUT/PATCH/DELETE
only when `allow_mutating` is enabled on the run, and even then confirmation
prefers the read path (e.g. prove IDOR by *reading* B's object, not deleting
it). See §7.

Output: each finding updated to `confirmed`/`dismissed` with per-role evidence,
streamed live (`on_findings`) like the AI stages, and a coverage line
("live-confirmed 6, enforced 11, inconclusive 3").

---

## 6. Credentials & authorization (the sensitive part)

**Encryption at rest.** A symmetric key from env/secret (`DAST_SECRET_KEY`,
Fernet/AES-GCM). `dast_credentials.secret_enc` is written encrypted, decrypted
only in the worker at send time. In prod this key comes from Key Vault, matching
how the Foundry key is handled.

**Never exposed.** Secrets are:
- returned by the API only as booleans (`secret_set: true`), like the Foundry
  key and Sonar token today;
- **never** placed in a finding, `raw`, an export, a log line, or an AI prompt.
  Evidence captures the request *line* and response *metadata*, with
  `Authorization`/`Cookie` headers redacted; full bodies are opt-in and
  secret-scrubbed;
- scoped to their target; a run only decrypts the creds for its own target.

**Authorization gate.** A `dast_run` cannot start until an operator explicitly
authorizes it for that target:
- The launch endpoint requires `Role.admin` (or a dedicated `pentester` role)
  and records `authorized_by` + `authorized_at`.
- The UI shows an explicit confirmation naming the exact `base_url` and the
  roles that will be used, and requires typing/clicking to confirm — this is
  outward-facing action, so it is never implicit.
- A machine-readable attestation ("I am authorized to test `<host>`") is stored
  on the run for the audit trail.

**Scope enforcement (defense in depth).** Every outbound request passes a guard
that checks the resolved host is in `allowed_hosts`; anything else is dropped
and logged, before it leaves the worker. Redirects are not followed across
hosts. This holds for both the app-native replay and (as far as we can constrain
it) the Burp scan configuration.

**Audit.** Every run logs target, roles used, who authorized it, when, and the
request count, into the existing `AgentEvent` stream and the run summary.

---

## 7. Active scan (Burp) — keeping it "safe"

"Safe active scan" per the chosen scope. Controls:
- **In-scope only.** Burp scan is configured with the target's `allowed_hosts`
  as its scope; we pass the discovered request surface (from the OpenAPI export
  we already generate) as seeds rather than letting it crawl outward.
- **Safe-by-default checks.** Prefer Burp's passive + "light" active audit; the
  operator opts into heavier/aggressive insertion points. No brute-force,
  no DoS-class checks.
- **Mutating methods** (POST/PUT/PATCH/DELETE) are gated by an `allow_mutating`
  flag on the run, off by default. With it off, the active scan is limited to
  safe/idempotent requests.
- **Rate limited** (`max_rps`) and cancellable — reuses the new immediate-cancel
  path (the worker's cancel watcher) so a live run stops fast.
- Results are pulled from Burp over MCP and normalized into `Finding`s
  (`source="dast"`), deduped against existing findings by URL+CWE.

---

## 8. API surface (sketch)

```
POST   /projects/{id}/dast-targets            create (admin)      {label, base_url, allowed_hosts?, active_scan_enabled, burp_mcp_id?, max_rps?}
GET    /projects/{id}/dast-targets            list (secrets masked)
PUT    /dast-targets/{id}                      update (admin)
DELETE /dast-targets/{id}
POST   /dast-targets/{id}/credentials          add role creds (admin; secret write-only)
DELETE /dast-credentials/{id}
POST   /dast-targets/{id}/test                 connectivity + auth smoke test (does a login as each role, no scanning)

POST   /scans/{scan_id}/dast                   launch a run (admin; body carries the authorization attestation,
                                               allow_mutating flag, which checks). Enqueues a worker job.
GET    /dast-runs/{id}                          status + summary
POST   /dast-runs/{id}/cancel                   reuse cancel machinery
```

All secret-bearing endpoints follow the existing masked-settings pattern
(`runtime_config`-style).

## 9. Worker / pipeline integration

- New job `run_dast(ctx, dast_run_id)` in `app/worker.py`, enqueued by the
  launch endpoint. Not part of the default source scan — it's a separate,
  explicitly-authorized run that references a completed `scan_id`.
- New stages surfaced in the existing stage panel:
  `dast_connect → dast_access → dast_active → dast_persist`.
- Reuses the streaming (`emit`/`on_findings`), checkpointing, and the new
  immediate-cancel watcher.
- Access-control step needs no Burp; active step is skipped with a logged reason
  if no Burp MCP is configured or reachable.

## 10. UI

- **Settings / Project:** a "DAST targets" card — add a target (base URL,
  allowed hosts, attach a Burp MCP server), add per-role credentials
  (write-only secret fields, `secret_set` badges), "Test connection" (logs in as
  each role, confirms reachability — no scanning).
- **Scan page:** a "Confirm live (DAST)" action, enabled once a target exists,
  behind the authorization confirmation dialog (names the host + roles).
- **Findings:** `access`/`dast` findings gain a live-verdict badge
  (`✓ confirmed live` / `🛡 enforced` / `? inconclusive`) and, expanded, the
  sanitized per-role request/response evidence. A "DAST" source tab.
- **Coverage panel:** a live-confirmation summary (confirmed / enforced /
  inconclusive / errored).

## 11. Phasing

1. **Phase 1 — targets & credentials.** Data model, encrypted secret storage,
   CRUD API + UI, connectivity/login "test". No traffic beyond the login test.
2. **Phase 2 — access-control replay.** The app-native loop (§5), scope guard,
   authorization gate, evidence capture, findings update, UI verdicts. This is
   the core precision feature and needs no Burp.
3. **Phase 3 — Burp active scan.** Register Burp MCP, seed it with the discovered
   surface, ingest results as `dast` findings.
4. **Phase 4 — object seeding & polish.** Id harvesting for IDOR, per-role
   matrices, richer evidence, OpenAPI/report exports of confirmed results.

Each phase is independently useful and independently reviewable; safety controls
(§6, §7) land in Phase 2 with the first outbound traffic.

## 12. Risks / open questions

- **Login flows vary** (form login, OAuth, CSRF tokens, MFA). Phase 1 supports
  static bearer/cookie/header; `login_form` (scripted login → capture session)
  is a Phase 2+ add. MFA-protected accounts are out of scope — use a test
  account without MFA.
- **Burp MCP API stability.** PortSwigger's MCP surface is new; we isolate it
  behind `mcp_client` so churn is contained.
- **Object seeding without operator input** risks acting on unexpected objects —
  hence the preference order in §5 and `inconclusive` rather than guessing.
- **State changes.** Even "safe" active scanning can change state. `allow_mutating`
  is off by default and the operator is warned; recommend a disposable/staging
  target.
- **Key management.** `DAST_SECRET_KEY` must be set for prod; if unset, credential
  storage is disabled (access-control replay with no stored creds still works via
  per-run in-memory creds as a fallback).

---

## 13. What I'd want confirmed before building Phase 2

- Is a staging/disposable target available, or will this point at production?
  (Changes the default for `allow_mutating` and how loud the warnings are.)
- Which auth kind do the target's test accounts use (bearer / cookie / form)?
- Should active-scan findings live in the same findings list (proposed) or a
  separate DAST report view?
