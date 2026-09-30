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
- **IDOR needs sample object ids.** They are auto-harvested from list endpoints
  per role; if none are found, set `object_seeds` on the target
  (`{"userB": {"id": ["7"]}}`) via the API, or the finding stays inconclusive.
- Object ids are shared per (role, param-name) across endpoints. If two
  endpoints use the param `id` for different object types, prefer harvesting or
  per-endpoint operator seeds to avoid cross-wiring.
- A canceled run keeps the verdicts it already wrote.

## 8. Limits

- One live run per scan at a time.
- Rate-limited (`max_rps`, default 5) with a hard request cap
  (`DAST_MAX_REQUESTS_PER_RUN`, default 5000).
- Cross-host redirects are never followed.
- Burp integration is verified against a mock MCP server; on first use against a
  real Burp, check the worker log for `burp seed failed` / `exposes no ... tool`
  and set tool-name overrides in the MCP server's config if the names differ.
