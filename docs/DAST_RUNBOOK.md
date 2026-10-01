# DAST runbook — confirming access control against a live target

This walks through setting up a live-test target, credentials (including a
scripted login), and running a confirmation against a deliberately-vulnerable
app. Design and safety model: `docs/DAST_DESIGN.md`.

> **Only test systems you are authorized to test.** Every run records who
> authorized it, and all traffic is confined to the host allow-list you set.
> Use a staging/disposable target where you can.

## 0. Prerequisites

- The stack is running (`docker compose up -d --build`).
- **`DAST_SECRET_KEY` is set** on the `api` and `worker` services (any strong
  random string). Without it, credential storage is disabled and you can only
  test unauthenticated cases. Add it to `.env`:
  ```
  DAST_SECRET_KEY=<64+ random chars>
  ```
  then `docker compose up -d` to apply.
- A completed source scan that **found endpoints** (the DAST run confirms that
  scan's access-control findings). Check the scan's "Endpoints" export is
  non-empty.

## 1. Stand up a practice target (optional)

To try it end to end, point at a known-vulnerable app you run yourself, e.g.
OWASP Juice Shop:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

From the stack's containers, that target is reachable at
`http://host.docker.internal:3000` (Mac/Windows) or the host IP (Linux).
Scan its source first (clone the repo, upload/scan it) so there are
access-control findings to confirm.

## 2. Create the target

Project page → **Live testing (DAST) targets** → *Add a target*:

- **Base URL**: e.g. `http://host.docker.internal:3000`
- **Extra allowed hosts** (optional): any other hosts the app legitimately uses
  (an API subdomain). The base URL's host is always included. Requests to any
  other host are dropped before they are sent.

## 3. Add test-account credentials

Add one credential per role you can log in as. At least two low-privilege
users (userA, userB) are needed to confirm IDOR; add an admin for BFLA.

**Static token / cookie** (simplest):
- kind `bearer` — paste an access token.
- kind `cookie` — paste the session cookie value (set the cookie name), or a
  raw `Cookie` header value (leave the name blank).
- kind `header` — a custom header name + value.

**Scripted login** (`login_form`) — the app logs in for you each run, so tokens
never go stale. The secret is a JSON spec:

```json
{
  "url": "/rest/user/login",
  "method": "POST",
  "content": "json",
  "body": {"email": "a@juice.test", "password": "..."},
  "apply": "bearer",
  "token_path": "authentication.token"
}
```

- `apply: "cookie"` instead captures the session cookie the login sets
  (optionally filter with `"cookie_names": ["session"]`).
- `token_path` is a dotted path into the JSON response.
- Mark the admin account **admin/priv** so it's used for BFLA and as the
  privileged identity when seeding Burp.

> MFA and OAuth logins are out of scope — use a plain test account.

## 4. Test the connection

Click **Test** on the target. It resolves any scripted logins and sends one
request per role to the base URL, reporting reachability and status. A ✓ means
the target is reachable and the credentials were accepted; it does not by
itself prove authorization (the run does that).

## 5. (Optional) enable the Burp active scan

1. In Burp Suite (Pro, 2025.x), install and start the **MCP Server** extension;
   note its URL.
2. **Settings → MCP servers**: register it (kind `burp`, transport `http`/`sse`,
   the URL).
3. On the target: tick **Active scan (Burp)** and select that MCP server.

## 6. Run the confirmation

Scan page → **Confirm findings live (DAST)**:

1. Pick the target.
2. **Run live confirmation** → the authorization dialog names the exact host and
   roles. Leave **allow state-changing requests** off unless you intend for
   POST/PUT/DELETE to be sent (prefer a disposable target if you enable it).
   Tick **Run Burp active scan** if configured.
3. **I'm authorized — run.**

The run streams progress into the scan page. Each access finding is driven to:

| Verdict | Meaning | Finding becomes |
|---|---|---|
| 🎯 confirmed live | the control is genuinely missing | **confirmed** |
| 🛡 enforced by app | the app correctly blocks it | **dismissed** (false positive) |
| live: inconclusive | not enough signal (e.g. no sample ids) | unchanged, note added |

Burp issues, if any, land under the **Live (DAST)** findings tab. Expand a
finding to see the per-role request/response evidence (auth redacted).

## 7. Interpreting results

- **IDOR confirmation** requires the attacker's response body to match the
  owner's own response for the same object (byte-for-byte). A 2xx whose body
  differs is reported *inconclusive*, not confirmed — verify those by hand.
- **IDOR needs sample object ids.** They are auto-harvested from each list
  endpoint per role and **keyed by collection**, so two endpoints that both use
  a param called `id` for different object types never share an id pool. If
  nothing is harvested for an endpoint, set `object_seeds` on the target as a
  fallback — either flat per role (`{"userB": {"id": ["7"]}}`, applies to any
  endpoint) or pinned to a collection
  (`{"userB": {"/orders": {"id": ["7"]}}}`, top precedence). Otherwise the
  finding stays inconclusive.
- A canceled run keeps the verdicts it already wrote.

## 8. Limits

- One live run per scan at a time.
- Rate-limited (`max_rps`, default 5) with a hard request cap
  (`DAST_MAX_REQUESTS_PER_RUN`, default 5000).
- Cross-host redirects are never followed.
- Burp integration is verified against a mock MCP server; on first use against a
  real Burp, check the worker log for `burp seed failed` / `exposes no ... tool`
  and set tool-name overrides in the MCP server's config if the names differ.

## Manual testing in Burp (Repeater / Intruder)

Every finding with an HTTP endpoint can be handed to Burp for manual testing:

- **Copy for Burp** (on a finding) — copies a raw HTTP/1.1 request. Object ids
  are wrapped in Intruder markers (`§1§`, or a sample UUID for UUID routes), so
  pasting into Intruder gives you the payload positions straight away.
- **→ Repeater / → Intruder** — with the Burp MCP server registered
  (Settings → Integrations), opens the request in Burp directly. In the
  Access control and Live (DAST) tabs you can send up to 50 at once.
- **Burp pack (Intruder)** (scan header) — a ZIP of raw requests for every
  medium/high-risk endpoint, a combined file annotated with related findings,
  id payload lists (`payloads/numeric-ids.txt`, `payloads/uuids-sample.txt`)
  and a how-to `README.txt`.

Requests carry `Authorization: Bearer REPLACE_WITH_YOUR_TOKEN`. Replace it, or
let a Burp session-handling rule / Autorize supply real sessions. Stored DAST
credentials are never exported or sent to Burp this way.

## Access-control findings: how they are verified

The regex pre-pass flags candidate problems (missing authentication, missing
role check, IDOR). These are hints, not findings:

1. Identifiers are classified as `numeric` (enumerable — IDOR directly
   exploitable), `uuid` (hard to guess — read-only routes are not flagged,
   write routes are low severity) or `unknown`.
2. If authentication can't be located for most routes, one "authentication
   mechanism not located" question replaces hundreds of per-route flags.
3. When AI review is on, flags are **not** shown until the AI gives each one
   an explicit verdict (confirmed / rejected / needs a human). Flags the main
   endpoint review skips get a focused second-chance triage with the handler
   code. Rejected flags, with the AI's reason, are listed under
   "why rejected?" on the Access control tab.
4. Anything the model still couldn't answer is kept but marked
   **unverified heuristic** and hidden by default (tick "Unverified
   heuristics" to see them).

For an existing scan with a flood of old flags, use **↻ Access control
(AI-verify)** on the scan page: it re-runs only this step and replaces only
the access-control findings.
