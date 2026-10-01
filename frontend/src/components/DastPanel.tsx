import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { DastRun, DastTarget, McpServer } from "../lib/types";
import { Button, Card, Input } from "./ui";

const AUTH_KINDS = ["bearer", "cookie", "header", "login_form"];

const LOGIN_SPEC_EXAMPLE = `{
  "url": "/api/login",
  "method": "POST",
  "content": "json",
  "body": {"username": "a@x.com", "password": "..."},
  "apply": "cookie",
  "token_path": "data.token",
  "header_name": "Authorization"
}`;

// ---------------------------------------------------------------------------
// Project page: manage live-test targets + their per-role credentials
// ---------------------------------------------------------------------------
export function DastTargetsCard({ projectId }: { projectId: string }) {
  const [targets, setTargets] = useState<DastTarget[]>([]);
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [hosts, setHosts] = useState("");
  const [msg, setMsg] = useState("");

  const [mcp, setMcp] = useState<McpServer[]>([]);
  const reload = () => api.listDastTargets(projectId).then(setTargets).catch(() => setTargets([]));
  useEffect(() => {
    reload();
    api.listMcp(projectId).then(setMcp).catch(() => setMcp([]));
  }, [projectId]);

  const create = async () => {
    if (!baseUrl.trim()) { setMsg("Base URL required"); return; }
    setMsg("");
    try {
      await api.createDastTarget(projectId, {
        label: label.trim() || undefined, base_url: baseUrl.trim(),
        allowed_hosts: hosts.split(",").map((h) => h.trim()).filter(Boolean),
      });
      setLabel(""); setBaseUrl(""); setHosts(""); await reload();
    } catch (e) { setMsg(String(e)); }
  };

  return (
    <Card className="p-4">
      <button onClick={() => setOpen((o) => !o)} className="flex items-center gap-2 w-full text-left">
        <span className="font-semibold text-sm">{open ? "▼" : "▶"} Live testing (DAST) targets</span>
        <span className="text-[11px] text-muted">{targets.length} configured</span>
      </button>
      {open && (
        <div className="mt-3 space-y-3">
          <p className="text-[11px] text-muted">
            Declare a running target you are authorised to test. A scan's access-control
            findings can then be confirmed live: each endpoint is replayed as different
            users to see whether the app actually enforces the control. Requests only ever
            reach the hosts you allow-list here.
          </p>
          {targets.map((t) => <TargetRow key={t.id} t={t} mcp={mcp} onChange={reload} />)}

          <div className="rounded border border-border p-3 space-y-2">
            <div className="text-xs font-medium">Add a target</div>
            <div className="grid grid-cols-2 gap-2">
              <Input placeholder="label (e.g. Staging)" value={label} onChange={(e) => setLabel(e.target.value)} />
              <Input placeholder="https://staging.example.com" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
            </div>
            <Input placeholder="extra allowed hosts (comma-separated, optional)" value={hosts} onChange={(e) => setHosts(e.target.value)} />
            <div className="flex items-center gap-2">
              <Button onClick={create}>Add target</Button>
              {msg && <span className="text-[11px] text-muted">{msg}</span>}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function TargetRow({ t, mcp, onChange }: { t: DastTarget; mcp: McpServer[]; onChange: () => void }) {
  const [test, setTest] = useState("");
  const [role, setRole] = useState("userA");
  const [kind, setKind] = useState("bearer");
  const [headerName, setHeaderName] = useState("");
  const [secret, setSecret] = useState("");
  const [priv, setPriv] = useState(false);
  const [msg, setMsg] = useState("");

  const runTest = async () => {
    setTest("testing…");
    try { const r = await api.testDastTarget(t.id); setTest(`${r.ok ? "✓" : "✗"} ${r.detail}`); }
    catch (e) { setTest(String(e)); }
  };
  const addCred = async () => {
    if (!secret) { setMsg("secret required"); return; }
    setMsg("");
    try {
      await api.addDastCredential(t.id, {
        role_label: role, auth_kind: kind, is_privileged: priv,
        header_name: headerName || undefined, secret,
      });
      setSecret(""); setHeaderName(""); onChange();
    } catch (e) { setMsg(String(e)); }
  };

  return (
    <div className="rounded border border-border p-3 text-sm space-y-2">
      <div className="flex items-center gap-2">
        <span className="font-medium">{t.label}</span>
        <span className="text-[11px] text-muted flex-1 truncate">
          {t.base_url} · scope: {t.allowed_hosts.join(", ")}
          {t.active_scan_enabled ? " · active scan on" : ""}
        </span>
        <Button variant="ghost" onClick={runTest}>Test</Button>
        <Button variant="ghost" onClick={() => api.deleteDastTarget(t.id).then(onChange)}>✕</Button>
      </div>
      {test && <div className="text-[11px] text-muted break-all">{test}</div>}

      <div className="flex flex-wrap gap-1.5">
        {t.credentials.map((c) => (
          <span key={c.id} className="text-[11px] px-1.5 py-0.5 rounded bg-border/60 flex items-center gap-1">
            {c.role_label} ({c.auth_kind}){c.is_privileged ? " ★" : ""}{c.secret_set ? "" : " ⚠ no secret"}
            <button className="text-muted hover:text-rose-300" onClick={() => api.deleteDastCredential(c.id).then(onChange)}>✕</button>
          </span>
        ))}
        {t.credentials.length === 0 && <span className="text-[11px] text-muted">No credentials yet.</span>}
      </div>
      <div className="text-[10px] text-muted">
        IDOR: sample object ids are auto-harvested from list endpoints as each role during a run.
      </div>

      {/* Active scan (Burp over MCP) */}
      <div className="flex flex-wrap items-center gap-2 text-[11px] border-t border-border pt-2">
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={t.active_scan_enabled}
            onChange={(e) => api.updateDastTarget(t.id, { active_scan_enabled: e.target.checked }).then(onChange)} />
          Active scan (Burp)
        </label>
        {t.active_scan_enabled && (
          <label className="flex items-center gap-1">
            Burp MCP server:
            <select value={t.burp_mcp_id || ""}
              onChange={(e) => api.updateDastTarget(t.id, { burp_mcp_id: e.target.value || null }).then(onChange)}
              className="px-1.5 py-1 rounded bg-bg border border-border">
              <option value="">— none —</option>
              {mcp.map((m) => <option key={m.id} value={m.id}>{m.name} ({m.kind})</option>)}
            </select>
          </label>
        )}
        {t.active_scan_enabled && !t.burp_mcp_id && (
          <span className="text-amber-300">register a Burp MCP server in Settings, then select it here</span>
        )}
      </div>
      {!t.secrets_available && (
        <div className="text-[11px] text-amber-300">
          Credential storage is off — set DAST_SECRET_KEY on the server to store test-account secrets.
        </div>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-[11px]">role
          <Input className="!py-1 !w-24" value={role} onChange={(e) => setRole(e.target.value)} />
        </label>
        <label className="text-[11px]">kind
          <select value={kind} onChange={(e) => setKind(e.target.value)}
            className="block mt-1 px-2 py-1.5 rounded-md bg-bg border border-border text-sm">
            {AUTH_KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
        </label>
        {(kind === "header" || kind === "cookie") && (
          <label className="text-[11px]">{kind === "cookie" ? "cookie name" : "header"}
            <Input className="!py-1 !w-28" value={headerName} onChange={(e) => setHeaderName(e.target.value)} />
          </label>
        )}
        {kind === "login_form" ? (
          <label className="text-[11px] flex-1 min-w-[16rem]">login spec (JSON)
            <textarea className="w-full mt-1 px-2 py-1 rounded-md bg-bg border border-border text-xs font-mono h-28"
              value={secret} onChange={(e) => setSecret(e.target.value)} disabled={!t.secrets_available}
              placeholder={LOGIN_SPEC_EXAMPLE} />
          </label>
        ) : (
          <label className="text-[11px] flex-1 min-w-[10rem]">secret (token / cookie value)
            <Input type="password" className="!py-1" value={secret} onChange={(e) => setSecret(e.target.value)}
              disabled={!t.secrets_available} />
          </label>
        )}
        <label className="text-[11px] flex items-center gap-1 pb-2">
          <input type="checkbox" checked={priv} onChange={(e) => setPriv(e.target.checked)} /> admin/priv
        </label>
        <Button variant="ghost" onClick={addCred} disabled={!t.secrets_available}>+ cred</Button>
      </div>
      {msg && <div className="text-[11px] text-muted">{msg}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan page: launch a run against a target (with an authorization gate)
// ---------------------------------------------------------------------------
export function DastLaunch({ scanId, projectId }: { scanId: string; projectId: string }) {
  const [targets, setTargets] = useState<DastTarget[]>([]);
  const [runs, setRuns] = useState<DastRun[]>([]);
  const [targetId, setTargetId] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [allowMutating, setAllowMutating] = useState(false);
  const [accessControl, setAccessControl] = useState(true);
  const [activeScan, setActiveScan] = useState(false);
  const [includePaths, setIncludePaths] = useState("");
  const [excludePaths, setExcludePaths] = useState("");
  const [plan, setPlan] = useState<any>(null);
  const [msg, setMsg] = useState("");

  const reload = () => {
    api.listDastTargets(projectId).then((t) => { setTargets(t); if (!targetId && t[0]) setTargetId(t[0].id); }).catch(() => {});
    api.listDastRuns(scanId).then(setRuns).catch(() => {});
  };
  useEffect(() => { reload(); }, [scanId, projectId]);
  useEffect(() => {
    if (!runs.some((r) => ["queued", "running"].includes(r.status))) return;
    const iv = setInterval(() => api.listDastRuns(scanId).then(setRuns).catch(() => {}), 2500);
    return () => clearInterval(iv);
  }, [runs.map((r) => r.status).join()]);

  const target = targets.find((t) => t.id === targetId);
  const splitPaths = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const opts = () => ({
    target_id: targetId, access_control: accessControl, active_scan: activeScan,
    include_paths: splitPaths(includePaths), exclude_paths: splitPaths(excludePaths),
  });

  const review = async () => {
    if (!targetId) return;
    setMsg(""); setPlan(null);
    try { setPlan(await api.dastPlan(scanId, opts())); setConfirming(true); }
    catch (e) { setMsg(String(e)); }
  };
  const launch = async () => {
    if (!target) return;
    setMsg("");
    try {
      await api.launchDast(scanId, { ...opts(), authorize: true, allow_mutating: allowMutating });
      setConfirming(false); setPlan(null); setAllowMutating(false); reload();
    } catch (e) { setMsg(String(e)); }
  };

  return (
    <Card className="p-4">
      <h2 className="font-semibold text-sm mb-2">Confirm findings live (DAST)</h2>
      {targets.length === 0 ? (
        <p className="text-[11px] text-muted">
          No live-test target configured. Add one on the project page to replay this scan's
          access-control findings against the running app.
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <select value={targetId} onChange={(e) => { setTargetId(e.target.value); setConfirming(false); setPlan(null); }}
              className="px-2 py-1.5 rounded-lg bg-bg border border-border text-sm flex-1">
              {targets.map((t) => <option key={t.id} value={t.id}>{t.label} — {t.base_url}</option>)}
            </select>
          </div>

          {/* what runs + where */}
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={accessControl} onChange={(e) => setAccessControl(e.target.checked)} />
              Confirm access-control findings
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={activeScan} onChange={(e) => setActiveScan(e.target.checked)} />
              Active scan (SQLi/XSS/headers{target?.burp_mcp_id ? " + Burp" : ""})
            </label>
            <label className="text-[11px] text-muted">only paths (optional)
              <input value={includePaths} onChange={(e) => setIncludePaths(e.target.value)}
                placeholder="/api, /admin" className="block w-full mt-0.5 px-2 py-1 rounded bg-bg border border-border text-xs text-slate-200" />
            </label>
            <label className="text-[11px] text-muted">exclude paths (optional)
              <input value={excludePaths} onChange={(e) => setExcludePaths(e.target.value)}
                placeholder="/logout" className="block w-full mt-0.5 px-2 py-1 rounded bg-bg border border-border text-xs text-slate-200" />
            </label>
          </div>

          <Button onClick={review}>Review plan →</Button>

          {confirming && plan && target && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs space-y-2">
              <div className="font-medium text-amber-200">Review before authorising</div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-slate-300">
                <div>Target: <b>{plan.target.base_url}</b></div>
                <div>In-scope hosts: {plan.target.allowed_hosts.join(", ")}</div>
                <div>Endpoints in scope: <b>{plan.endpoints_in_scope}</b></div>
                <div>Access findings to confirm: <b>{plan.access_findings_to_confirm}</b></div>
                <div>Roles: {plan.roles.join(", ")}</div>
                <div>Est. requests: <b>~{plan.estimated_requests}</b> @ {plan.rate_limit_rps}/s</div>
              </div>
              {Object.keys(plan.access_by_kind || {}).length > 0 && (
                <div className="text-muted">Checks: {Object.entries(plan.access_by_kind).map(([k, n]) => `${k} ×${n}`).join(", ")}
                  {plan.checks.active_scan && " · active scan" }{plan.checks.burp && " · Burp" }</div>
              )}
              <label className="flex items-center gap-1.5">
                <input type="checkbox" checked={allowMutating} onChange={(e) => setAllowMutating(e.target.checked)} />
                Allow state-changing requests (POST/PUT/DELETE) — off by default
              </label>
              <div className="text-amber-200/90">Only run against systems you are authorised to test.</div>
              <div className="flex gap-2 pt-1">
                <Button variant="primary" onClick={launch}>I'm authorised — run</Button>
                <Button variant="ghost" onClick={() => { setConfirming(false); setPlan(null); }}>Cancel</Button>
              </div>
            </div>
          )}
          {msg && <div className="text-[11px] text-rose-300">{msg}</div>}
          {runs.map((r) => <RunRow key={r.id} r={r} onCancel={() => api.cancelDastRun(r.id).then(reload)} />)}
        </div>
      )}
    </Card>
  );
}

const PURPOSE_LABEL: Record<string, string> = {
  "access:missing_authn": "missing-auth probe", "access:bfla": "privilege probe",
  "access:idor": "IDOR probe", "access:idor-baseline": "IDOR owner baseline",
  harvest: "id harvest", login: "login", "passive:headers": "security headers",
  "passive:errors": "error check", "active:sqli": "SQLi probe", "active:xss": "XSS probe",
};

function RunRow({ r, onCancel }: { r: DastRun; onCancel: () => void }) {
  const s = r.summary || {};
  const live = ["queued", "running"].includes(r.status);
  const [showLog, setShowLog] = useState(false);
  const log: any[] = s.requests_log || [];
  const byPurpose: Record<string, number> = s.by_purpose || {};
  return (
    <div className="rounded-lg border border-border text-[11px]">
      <div className="p-2 flex items-center gap-2">
        <span className={`px-1.5 py-0.5 rounded ${
          r.status === "completed" ? "bg-emerald-500/15 text-emerald-300" :
          r.status === "failed" ? "bg-rose-500/15 text-rose-300" :
          live ? "bg-sky-500/15 text-sky-300" : "bg-border/60"}`}>{r.status}</span>
        <span className="flex-1 text-muted">
          {typeof s.confirmed === "number"
            ? `${s.confirmed} confirmed · ${s.enforced} enforced · ${s.inconclusive} inconclusive · ${s.requests ?? 0} requests`
              + (typeof s.active_issues === "number" ? ` · ${s.active_issues} active findings` : "")
              + (typeof s.burp_issues === "number" ? ` · ${s.burp_issues} Burp` : "")
            : r.error || (live ? "running…" : "")}
        </span>
        {r.authorized_by && <span className="text-muted">by {r.authorized_by}</span>}
        {log.length > 0 && <button className="text-accent-hover hover:underline" onClick={() => setShowLog((v) => !v)}>
          {showLog ? "hide" : "requests"}</button>}
        {live && <button className="text-rose-300 hover:underline" onClick={onCancel}>cancel</button>}
      </div>
      {showLog && (
        <div className="border-t border-border p-2 space-y-2">
          {Object.keys(byPurpose).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(byPurpose).map(([p, n]) => (
                <span key={p} className="px-1.5 py-0.5 rounded bg-border/60">
                  {PURPOSE_LABEL[p] || p}: {n}
                </span>
              ))}
            </div>
          )}
          <div className="max-h-56 overflow-auto font-mono text-[10px]">
            <table className="w-full">
              <tbody>
                {log.map((e, i) => (
                  <tr key={i} className="border-b border-border/40">
                    <td className="pr-2 text-muted">{PURPOSE_LABEL[e.purpose] || e.purpose}</td>
                    <td className="pr-2">{e.method}</td>
                    <td className="pr-2 truncate max-w-md">{e.url}</td>
                    <td className="pr-2">{e.identity}</td>
                    <td className={e.status && e.status < 400 ? "text-emerald-400" : "text-amber-400"}>
                      {e.note || e.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
