import { useEffect, useState } from "react";
import { Button, Card, Input } from "../components/ui";
import { api } from "../lib/api";
import type { FoundrySettings, McpServer } from "../lib/types";

export default function SettingsPage() {
  const [fs, setFs] = useState<FoundrySettings>();
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [deployment, setDeployment] = useState("");
  const [apiVersion, setApiVersion] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [test, setTest] = useState<string>("");
  const [mcp, setMcp] = useState<McpServer[]>([]);
  const [newMcp, setNewMcp] = useState({ name: "", kind: "semgrep", transport: "http", url: "" });
  const [msg, setMsg] = useState("");

  const load = async () => {
    const s = await api.getFoundry();
    setFs(s); setEndpoint(s.endpoint || ""); setDeployment(s.deployment); setApiVersion(s.api_version);
    api.listModels().then((m) => setModels(m.models)).catch(() => {});
    api.listMcp().then(setMcp).catch(() => {});
  };
  useEffect(() => { load().catch((e) => setMsg(String(e))); }, []);

  const save = async () => {
    setMsg("");
    const body: Record<string, any> = { endpoint, deployment, api_version: apiVersion };
    if (apiKey) body.api_key = apiKey;
    try { await api.updateFoundry(body); setApiKey(""); setMsg("Saved ✓"); await load(); }
    catch (e) { setMsg(String(e)); }
  };

  const runTest = async () => {
    setTest("testing…");
    const r = await api.testFoundry();
    setTest(`${r.ok ? "✓" : "✗"} ${r.detail}${r.models.length ? ` · models: ${r.models.join(", ")}` : ""}`);
    if (r.models.length) setModels(r.models);
  };

  const addMcp = async () => {
    if (!newMcp.name) return;
    await api.createMcp(newMcp);
    setNewMcp({ name: "", kind: "semgrep", transport: "http", url: "" });
    api.listMcp().then(setMcp);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <Card className="p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">Azure AI Foundry connection</h2>
          {fs && (
            <span className={`text-xs px-2 py-0.5 rounded border ${fs.mock_mode ? "border-amber-500/40 text-amber-300" : "border-emerald-500/40 text-emerald-300"}`}>
              {fs.mock_mode ? "MOCK MODE" : `connected · ${fs.auth_mode}`}
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <label className="text-sm">Endpoint URL
            <Input value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://my-foundry.openai.azure.com" />
          </label>
          <label className="text-sm">API key {fs?.api_key_set && <span className="text-emerald-400 text-xs">(set)</span>}
            <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              placeholder={fs?.api_key_set ? "•••••• (unchanged)" : "paste key"} />
          </label>
          <label className="text-sm">Model / deployment name
            <Input value={deployment} onChange={(e) => setDeployment(e.target.value)}
              placeholder="e.g. gpt-4o, my-codex-deployment" list="models-list" />
            <datalist id="models-list">
              {models.map((m) => <option key={m} value={m} />)}
            </datalist>
            {models.length > 0 && (
              <div className="text-[11px] text-muted mt-1">Discovered: {models.join(", ")}</div>
            )}
          </label>
          <label className="text-sm">API version
            <Input value={apiVersion} onChange={(e) => setApiVersion(e.target.value)} />
          </label>
        </div>
        <div className="flex items-center gap-3 mt-4">
          <Button onClick={save}>Save</Button>
          <Button variant="ghost" onClick={runTest}>Test connection</Button>
          {msg && <span className="text-sm text-muted">{msg}</span>}
          {test && <span className="text-sm text-muted">{test}</span>}
        </div>
        <p className="text-xs text-muted mt-3">
          Leave the endpoint blank to run the agent in deterministic mock mode (no Azure required).
          In production the API key is backed by Key Vault.
        </p>
      </Card>

      <Card className="p-4">
        <h2 className="font-semibold mb-3">MCP servers (Semgrep / SonarQube / custom)</h2>
        <div className="grid grid-cols-5 gap-2 mb-3">
          <Input placeholder="name" value={newMcp.name} onChange={(e) => setNewMcp({ ...newMcp, name: e.target.value })} />
          <select value={newMcp.kind} onChange={(e) => setNewMcp({ ...newMcp, kind: e.target.value })}
            className="px-2 rounded-md bg-bg border border-border text-sm">
            <option>semgrep</option><option>sonarqube</option><option>custom</option>
          </select>
          <select value={newMcp.transport} onChange={(e) => setNewMcp({ ...newMcp, transport: e.target.value })}
            className="px-2 rounded-md bg-bg border border-border text-sm">
            <option>http</option><option>sse</option><option>stdio</option>
          </select>
          <Input placeholder="url" value={newMcp.url} onChange={(e) => setNewMcp({ ...newMcp, url: e.target.value })} />
          <Button onClick={addMcp}>Add</Button>
        </div>
        <div className="space-y-1">
          {mcp.map((m) => (
            <div key={m.id} className="flex items-center justify-between px-3 py-2 rounded border border-border text-sm">
              <span>{m.name} <span className="text-muted text-xs">· {m.kind} · {m.transport} · {m.url}</span></span>
              <div className="flex items-center gap-2">
                <span className={`text-xs ${m.enabled ? "text-emerald-400" : "text-muted"}`}>{m.enabled ? "enabled" : "disabled"}</span>
                <Button variant="ghost" onClick={() => api.deleteMcp(m.id).then(() => api.listMcp().then(setMcp))}>Remove</Button>
              </div>
            </div>
          ))}
          {mcp.length === 0 && <div className="text-muted text-sm">No MCP servers registered.</div>}
        </div>
      </Card>
    </div>
  );
}
