import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { DastRun, DastTarget } from "../lib/types";
import { Button, Card, Input } from "./ui";

const AUTH_KINDS = ["bearer", "cookie", "header"];

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

  const reload = () => api.listDastTargets(projectId).then(setTargets).catch(() => setTargets([]));
  useEffect(() => { reload(); }, [projectId]);

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
            Declare a running target you are authorized to test. A scan's access-control
            findings can then be confirmed live: each endpoint is replayed as different
            users to see whether the app actually enforces the control. Requests only ever
            reach the hosts you allow-list here.
          </p>
          {targets.map((t) => <TargetRow key={t.id} t={t} onChange={reload} />)}

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

function TargetRow({ t, onChange }: { t: DastTarget; onChange: () => void }) {
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
        <label className="text-[11px] flex-1 min-w-[10rem]">secret (token / cookie value)
          <Input type="password" className="!py-1" value={secret} onChange={(e) => setSecret(e.target.value)}
            disabled={!t.secrets_available} />
        </label>
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
  const launch = async () => {
    if (!target) return;
    setMsg("");
    try {
      await api.launchDast(scanId, { target_id: targetId, authorize: true, allow_mutating: allowMutating });
      setConfirming(false); setAllowMutating(false); reload();
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
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <select value={targetId} onChange={(e) => setTargetId(e.target.value)}
              className="px-2 py-1.5 rounded-md bg-bg border border-border text-sm flex-1">
              {targets.map((t) => <option key={t.id} value={t.id}>{t.label} — {t.base_url}</option>)}
            </select>
            <Button onClick={() => setConfirming(true)}>Run live confirmation</Button>
          </div>
          {confirming && target && (
            <div className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs space-y-2">
              <div className="text-amber-200">
                This sends live requests to <b>{target.base_url}</b> (hosts: {target.allowed_hosts.join(", ")})
                as {target.credentials.length} configured role(s). Only run this against systems you are
                authorized to test.
              </div>
              <label className="flex items-center gap-1.5">
                <input type="checkbox" checked={allowMutating} onChange={(e) => setAllowMutating(e.target.checked)} />
                Allow state-changing requests (POST/PUT/DELETE) — off by default
              </label>
              <div className="flex gap-2">
                <Button variant="primary" onClick={launch}>I'm authorized — run</Button>
                <Button variant="ghost" onClick={() => setConfirming(false)}>Cancel</Button>
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

function RunRow({ r, onCancel }: { r: DastRun; onCancel: () => void }) {
  const s = r.summary || {};
  const live = ["queued", "running"].includes(r.status);
  return (
    <div className="rounded border border-border p-2 text-[11px] flex items-center gap-2">
      <span className={`px-1.5 py-0.5 rounded ${
        r.status === "completed" ? "bg-emerald-500/15 text-emerald-300" :
        r.status === "failed" ? "bg-rose-500/15 text-rose-300" :
        live ? "bg-sky-500/15 text-sky-300" : "bg-border/60"}`}>{r.status}</span>
      <span className="flex-1 text-muted">
        {typeof s.confirmed === "number"
          ? `${s.confirmed} confirmed · ${s.enforced} enforced · ${s.inconclusive} inconclusive · ${s.requests ?? 0} requests`
          : r.error || (live ? "running…" : "")}
      </span>
      {r.authorized_by && <span className="text-muted">by {r.authorized_by}</span>}
      {live && <button className="text-rose-300 hover:underline" onClick={onCancel}>cancel</button>}
    </div>
  );
}
