import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button, Card, SeverityBadge, Spinner, StateBadge } from "../components/ui";
import { useScanEvents } from "../hooks/useScanEvents";
import { api } from "../lib/api";
import type { ChatMessage, Endpoint, Finding, Scan } from "../lib/types";

export default function ScanPage() {
  const { scanId } = useParams();
  const nav = useNavigate();
  const { events, status, narration, live } = useScanEvents(scanId);
  const [scan, setScan] = useState<Scan>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [chat, setChat] = useState<ChatMessage[]>([]);
  const [msg, setMsg] = useState("");
  const [sending, setSending] = useState(false);

  const refresh = () => {
    if (!scanId) return;
    api.getScan(scanId).then(setScan).catch(() => {});
    api.listFindings(scanId).then(setFindings).catch(() => {});
  };
  useEffect(() => { refresh(); api.listChat(scanId!).then(setChat).catch(() => {}); }, [scanId]);

  // Re-pull authoritative findings whenever a finding lands or the scan finishes.
  const lastType = events[events.length - 1]?.type;
  useEffect(() => {
    if (["finding", "done", "failed"].includes(lastType || "")) refresh();
  }, [events.length]);

  // Surface chat events streamed from the server (e.g. during-scan questions).
  useEffect(() => {
    const chats = events.filter((e) => e.type === "chat");
    if (chats.length) api.listChat(scanId!).then(setChat).catch(() => {});
  }, [events.length]);

  const send = async () => {
    if (!msg.trim() || !scanId) return;
    setSending(true);
    try { await api.postChat(scanId, msg.trim()); setMsg(""); await api.listChat(scanId).then(setChat); }
    finally { setSending(false); }
  };

  const triage = async (id: string, state: string) => {
    await api.triageFinding(id, { state });
    refresh();
  };

  return (
    <div>
      <button onClick={() => nav(-1)} className="text-sm text-muted hover:text-slate-200 mb-2">← Back</button>
      <div className="flex items-center gap-3 mb-4">
        <h1 className="text-2xl font-bold">Scan</h1>
        <span className="px-2 py-0.5 rounded text-xs border border-border flex items-center gap-1">
          {live && <Spinner />} {status || scan?.status}
        </span>
        {(scan?.status === "running" || scan?.status === "queued") &&
          <Button variant="danger" onClick={() => api.cancelScan(scanId!).then(refresh)}>Cancel</Button>}
        {scan?.status && !["queued", "running"].includes(scan.status) && (
          <div className="flex gap-1 ml-auto">
            <ExportBtn scanId={scanId!} format="burp" label="Burp XML" />
            <ExportBtn scanId={scanId!} format="sarif" label="SARIF" />
            <ExportBtn scanId={scanId!} format="csv" label="CSV" />
            <ExportBtn scanId={scanId!} format="endpoints" label="Endpoints" />
          </div>
        )}
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 space-y-6">
          <Card className="p-4">
            <h2 className="font-semibold mb-2 text-sm">Reviewer output {live && "(live)"}</h2>
            <pre className="text-xs whitespace-pre-wrap text-slate-300 max-h-48 overflow-auto">
              {narration || "Waiting for the agent…"}
            </pre>
            <div className="mt-2 space-y-0.5 max-h-32 overflow-auto">
              {events.filter((e) => ["status", "log"].includes(e.type)).map((e, i) => (
                <div key={i} className="text-[11px] text-muted">
                  · {e.status ? `status: ${e.status}` : e.message}
                </div>
              ))}
            </div>
          </Card>

          <div>
            <h2 className="font-semibold mb-2">Findings ({findings.length})</h2>
            <div className="space-y-2">
              {findings.map((f) => <FindingRow key={f.id} f={f} onTriage={triage} />)}
              {findings.length === 0 && <div className="text-muted text-sm">No findings yet.</div>}
            </div>
          </div>

          {scan?.summary?.endpoints?.length > 0 && (
            <EndpointsPanel endpoints={scan.summary.endpoints} />
          )}
        </div>

        <ChatPanel chat={chat} msg={msg} setMsg={setMsg} send={send} sending={sending} />
      </div>
    </div>
  );
}

function FindingRow({ f, onTriage }: { f: Finding; onTriage: (id: string, s: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <Card className="p-3">
      <div className="flex items-center gap-3 cursor-pointer" onClick={() => setOpen((o) => !o)}>
        <SeverityBadge severity={f.severity} />
        <span className="flex-1 font-medium text-sm">{f.title}</span>
        {f.cwe && <span className="text-[11px] text-muted">{f.cwe}</span>}
        <StateBadge state={f.state} />
      </div>
      <div className="flex items-center gap-2 mt-1 text-[11px] text-muted">
        {f.file_path && <span>{f.file_path}:{f.line_start}</span>}
        {f.raw?.reviewed_by && <span className="px-1.5 rounded bg-border/60">🔍 {f.raw.reviewed_by}</span>}
        {f.raw?.merged_count && f.raw.merged_count > 1 && <span>×{f.raw.merged_count} reviewers</span>}
        {f.triaged_by && <span className="px-1.5 rounded bg-border/60">⚖ {f.triaged_by}</span>}
      </div>
      {open && (
        <div className="mt-3 text-sm space-y-2">
          <p className="text-slate-300">{f.description}</p>
          {f.triage_note && <p className="text-xs text-amber-300/90">⚖ {f.triage_note}</p>}
          {f.code_snippet && <pre className="text-xs bg-bg border border-border rounded p-2 overflow-auto">{f.code_snippet}</pre>}
          {f.remediation && <p className="text-xs"><span className="text-emerald-400">Fix:</span> {f.remediation}</p>}
          {f.human_question && (
            <div className="text-xs p-2 rounded border border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-200">
              ❓ {f.human_question}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button variant="ghost" onClick={() => onTriage(f.id, "confirmed")}>Confirm</Button>
            <Button variant="ghost" onClick={() => onTriage(f.id, "dismissed")}>Dismiss (FP)</Button>
            <Button variant="ghost" onClick={() => onTriage(f.id, "needs_info")}>Needs review</Button>
          </div>
        </div>
      )}
    </Card>
  );
}

function ExportBtn({ scanId, format, label }: { scanId: string; format: string; label: string }) {
  return (
    <a href={api.exportUrl(scanId, format)} target="_blank" rel="noreferrer"
      className="px-2 py-1 rounded text-xs border border-border hover:bg-border text-slate-300">
      {label}
    </a>
  );
}

function EndpointsPanel({ endpoints }: { endpoints: Endpoint[] }) {
  const [open, setOpen] = useState(false);
  const unauthCount = endpoints.filter((e) => e.auth_hints.length === 0).length;
  return (
    <Card className="p-4">
      <button onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 w-full text-left">
        <span className="text-sm font-semibold">
          {open ? "▼" : "▶"} Discovered endpoints ({endpoints.length})
        </span>
        {unauthCount > 0 && (
          <span className="text-xs text-amber-400">{unauthCount} without auth</span>
        )}
      </button>
      {open && (
        <div className="mt-2 max-h-64 overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-muted border-b border-border">
                <th className="text-left px-2 py-1">Method</th>
                <th className="text-left px-2 py-1">Path</th>
                <th className="text-left px-2 py-1">Handler</th>
                <th className="text-left px-2 py-1">File</th>
                <th className="text-left px-2 py-1">Auth</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep, i) => (
                <tr key={i} className={`border-b border-border/50 ${ep.auth_hints.length === 0 ? "text-amber-300/80" : ""}`}>
                  <td className="px-2 py-0.5 font-mono">{ep.method}</td>
                  <td className="px-2 py-0.5 font-mono">{ep.path}</td>
                  <td className="px-2 py-0.5 text-muted">{ep.handler}</td>
                  <td className="px-2 py-0.5 text-muted">{ep.file_path}:{ep.line}</td>
                  <td className="px-2 py-0.5">
                    {ep.auth_hints.length > 0
                      ? <span className="text-emerald-400">{ep.auth_hints.join(", ")}</span>
                      : <span className="text-amber-400">none</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function ChatPanel({ chat, msg, setMsg, send, sending }: {
  chat: ChatMessage[]; msg: string; setMsg: (s: string) => void; send: () => void; sending: boolean;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [chat.length]);
  return (
    <Card className="p-4 flex flex-col h-[70vh]">
      <h2 className="font-semibold mb-2 text-sm">Interact with the reviewer</h2>
      <div className="flex-1 overflow-auto space-y-2">
        {chat.map((m) => (
          <div key={m.id} className={`text-sm p-2 rounded-md ${m.role === "user" ? "bg-emerald-600/15 ml-6" : "bg-bg border border-border mr-6"}`}>
            <div className="text-[10px] uppercase text-muted mb-0.5">{m.role}</div>
            {m.content}
          </div>
        ))}
        {chat.length === 0 && <div className="text-muted text-sm">Ask about a finding, refocus the review, or answer the agent's questions — during or after the scan.</div>}
        <div ref={endRef} />
      </div>
      <div className="mt-2 flex gap-2">
        <input value={msg} onChange={(e) => setMsg(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()} placeholder="Message…"
          className="flex-1 px-3 py-2 rounded-md bg-bg border border-border text-sm outline-none" />
        <Button onClick={send} disabled={sending}>{sending ? "…" : "Send"}</Button>
      </div>
    </Card>
  );
}
