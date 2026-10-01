import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { McpServer } from "../lib/types";

// One fetch per page load: the registered Burp MCP server, if any.
let burpP: Promise<McpServer | null> | null = null;
export function useBurpServer(): McpServer | null {
  const [s, setS] = useState<McpServer | null>(null);
  useEffect(() => {
    burpP ??= api.listMcp().then((l) => l.find((m) => m.kind === "burp" && m.enabled) ?? null)
      .catch(() => null);
    burpP.then(setS);
  }, []);
  return s;
}

const btn = "px-2 py-1 rounded-md text-xs border border-border hover:bg-border text-slate-200 disabled:opacity-40";

/** Copy a finding's endpoint as an Intruder-ready request, or push it into
 *  Burp Repeater / Intruder through the Burp MCP server. */
export function BurpActions({ findingId }: { findingId: string }) {
  const burp = useBurpServer();
  const [msg, setMsg] = useState("");
  const [raw, setRaw] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const copy = async () => {
    setMsg("");
    try {
      const r = await api.findingBurpRequest(findingId);
      try {
        await navigator.clipboard.writeText(r.raw);
        setMsg(`Copied — paste into Repeater/Intruder (target ${r.host}:${r.port}${r.https ? " HTTPS" : ""})`);
        setRaw(null);
      } catch {
        setRaw(r.raw);  // clipboard needs https/localhost: show it to copy by hand
        setMsg("Clipboard unavailable here — copy the request below");
      }
    } catch (e) { setMsg(String(e)); }
  };
  const send = async (tool: "repeater" | "intruder") => {
    if (!burp) return;
    setBusy(true); setMsg("");
    try {
      const r = await api.burpSend({ mcp_id: burp.id, tool, finding_ids: [findingId] });
      setMsg(r.sent ? `Opened in Burp ${tool === "repeater" ? "Repeater" : "Intruder"} ✓` : r.errors.join("; "));
    } catch (e) { setMsg(String(e)); } finally { setBusy(false); }
  };

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <button className={btn} onClick={copy} title="Raw HTTP request with § markers on object ids">⧉ Copy for Burp</button>
        {burp && <>
          <button className={btn} disabled={busy} onClick={() => send("repeater")}>→ Repeater</button>
          <button className={btn} disabled={busy} onClick={() => send("intruder")}>→ Intruder</button>
        </>}
        {msg && <span className="text-[11px] text-muted">{msg}</span>}
      </div>
      {raw && (
        <textarea readOnly value={raw} onFocus={(e) => e.currentTarget.select()}
          className="w-full h-40 font-mono text-[11px] bg-bg border border-border rounded p-2" />
      )}
    </div>
  );
}

/** Bulk: push up to 50 findings into Burp at once. */
export function BurpBulkSend({ findingIds }: { findingIds: string[] }) {
  const burp = useBurpServer();
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  if (!burp || findingIds.length === 0) return null;
  const ids = findingIds.slice(0, 50);
  const send = async (tool: "repeater" | "intruder") => {
    if (!confirm(`Open ${ids.length} request(s) in Burp ${tool}?`)) return;
    setBusy(true); setMsg("");
    try {
      const r = await api.burpSend({ mcp_id: burp.id, tool, finding_ids: ids });
      setMsg(`${r.sent} sent${r.errors.length ? ` · ${r.errors.length} failed: ${r.errors[0]}` : ""}`);
    } catch (e) { setMsg(String(e)); } finally { setBusy(false); }
  };
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span className="text-muted">Burp:</span>
      <button className={btn} disabled={busy} onClick={() => send("repeater")}>
        {ids.length} → Repeater</button>
      <button className={btn} disabled={busy} onClick={() => send("intruder")}>
        {ids.length} → Intruder</button>
      {msg && <span className="text-muted">{msg}</span>}
    </div>
  );
}
