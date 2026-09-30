import { useEffect, useState } from "react";
import { Button, Card, Input } from "../components/ui";
import { api } from "../lib/api";
import type {
  AiProfile, FoundrySettings, McpServer, ModelRole, ModelRoles, ProfileKind, ScannerSettings,
} from "../lib/types";

const emptyRole = (deployment = ""): ModelRole => ({ deployment, transport: "auto", reasoning_effort: null });

const NO_ROLES = { chat: null, reviewers: [], judge: null, exploit: null, verifier: null };

// Starting points for a new profile. "current" snapshots the saved settings
// (API key included, server-side); the rest are local/cloud presets.
const TEMPLATES: Record<string, { label: string; fromCurrent?: boolean; settings?: Record<string, any> }> = {
  current: { label: "Current settings (incl. API key)", fromCurrent: true },
  ollama: {
    label: "Local · Ollama",
    settings: { endpoint: "http://host.docker.internal:11434", api_style: "local", api_version: "",
      deployment: "qwen2.5-coder:32b", context_tokens: 32768, concurrency: 1, roles: NO_ROLES },
  },
  lmstudio: {
    label: "Local · LM Studio / vLLM",
    settings: { endpoint: "http://host.docker.internal:1234", api_style: "local", api_version: "",
      deployment: "local-model", context_tokens: 32768, concurrency: 1, roles: NO_ROLES },
  },
  azure: {
    label: "Cloud · Azure AI Foundry",
    settings: { endpoint: "https://YOUR-RESOURCE.services.ai.azure.com", api_style: "v1",
      api_version: "preview", deployment: "gpt-5-codex", concurrency: 4, roles: NO_ROLES },
  },
  mock: {
    label: "Mock (offline, no AI)",
    settings: { endpoint: "", api_style: "v1", deployment: "mock", roles: NO_ROLES },
  },
};

const KIND_STYLE: Record<ProfileKind, string> = {
  local: "border-sky-500/40 text-sky-300",
  cloud: "border-violet-500/40 text-violet-300",
  mock: "border-amber-500/40 text-amber-300",
};

const toNum = (s: string): number | null => {
  const n = parseInt(s, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
};

export default function SettingsPage() {
  const [fs, setFs] = useState<FoundrySettings>();
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [deployment, setDeployment] = useState("");
  const [apiVersion, setApiVersion] = useState("");
  const [apiStyle, setApiStyle] = useState("v1");
  const [contextTokens, setContextTokens] = useState("");
  const [concurrency, setConcurrency] = useState("");
  const [roles, setRoles] = useState<ModelRoles>({ reviewers: [] });
  const [models, setModels] = useState<string[]>([]);
  const [test, setTest] = useState<string>("");
  const [mcp, setMcp] = useState<McpServer[]>([]);
  const [newMcp, setNewMcp] = useState({ name: "", kind: "semgrep", transport: "http", url: "" });
  const [msg, setMsg] = useState("");
  const [scanners, setScanners] = useState<ScannerSettings>();
  const [sonarUrl, setSonarUrl] = useState("");
  const [sonarToken, setSonarToken] = useState("");
  const [scanMsg, setScanMsg] = useState("");
  const [sonarTest, setSonarTest] = useState("");

  const load = async () => {
    const s = await api.getFoundry();
    setFs(s); setEndpoint(s.endpoint || ""); setDeployment(s.deployment); setApiVersion(s.api_version);
    setApiStyle(s.api_style || "v1");
    setContextTokens(s.context_tokens ? String(s.context_tokens) : "");
    setConcurrency(s.concurrency ? String(s.concurrency) : "");
    setRoles({
      chat: s.roles?.chat ?? null,
      reviewers: s.roles?.reviewers?.length ? s.roles.reviewers : [],
      judge: s.roles?.judge ?? null,
      exploit: s.roles?.exploit ?? null,
      verifier: s.roles?.verifier ?? null,
    });
    api.listModels().then((m) => setModels(m.models)).catch(() => {});
    api.listMcp().then(setMcp).catch(() => {});
    api.getScanners().then((sc) => { setScanners(sc); setSonarUrl(sc.sonarqube_url || ""); }).catch(() => {});
  };
  useEffect(() => { load().catch((e) => setMsg(String(e))); }, []);

  const patchScanners = async (patch: Record<string, any>) => {
    setScanMsg("");
    try {
      const sc = await api.updateScanners(patch);
      setScanners(sc); setSonarToken(""); setScanMsg("Saved ✓");
    } catch (e) { setScanMsg(String(e)); }
  };

  const saveSonar = () => {
    const patch: Record<string, any> = { sonarqube_url: sonarUrl };
    if (sonarToken) patch.sonarqube_token = sonarToken;
    return patchScanners(patch);
  };

  const runSonarTest = async () => {
    setSonarTest("testing…");
    try { const r = await api.testSonar(); setSonarTest(`${r.ok ? "✓" : "✗"} ${r.detail}`); }
    catch (e) { setSonarTest(String(e)); }
  };

  const save = async () => {
    setMsg("");
    const cleanRoles: ModelRoles = {
      chat: roles.chat?.deployment ? roles.chat : null,
      reviewers: roles.reviewers.filter((r) => r.deployment.trim()),
      judge: roles.judge?.deployment ? roles.judge : null,
      exploit: roles.exploit?.deployment ? roles.exploit : null,
      verifier: roles.verifier?.deployment ? roles.verifier : null,
    };
    const body: Record<string, any> = {
      endpoint, deployment, api_version: apiVersion, api_style: apiStyle, roles: cleanRoles,
      context_tokens: toNum(contextTokens), concurrency: toNum(concurrency),
    };
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

      <ProfilesCard activeId={fs?.active_profile_id ?? null}
        onActivated={() => load().catch((e) => setMsg(String(e)))} />

      <Card className="p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="font-semibold">AI reviewer connection</h2>
            <div className="text-[11px] text-muted mt-0.5">
              {fs?.active_profile_name
                ? <>Editing profile <span className="text-slate-200 font-medium">{fs.active_profile_name}</span> — saving updates it.</>
                : "Active settings (not saved as a profile)."}
            </div>
          </div>
          {fs && (
            <span className={`text-xs px-2 py-0.5 rounded border ${fs.mock_mode ? "border-amber-500/40 text-amber-300" : "border-emerald-500/40 text-emerald-300"}`}>
              {fs.mock_mode ? "MOCK MODE" : `${fs.kind ?? "connected"} · ${fs.auth_mode}`}
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <label className="text-sm">Endpoint URL
            <Input value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
              placeholder="http://localhost:11434 or https://my-foundry.openai.azure.com" />
          </label>
          <label className="text-sm">API key {fs?.api_key_set && <span className="text-emerald-400 text-xs">(set)</span>}
            <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              placeholder={fs?.api_key_set ? "•••••• (unchanged)" : "paste key"} />
          </label>
          <label className="text-sm">Model / deployment name
            <Input value={deployment} onChange={(e) => setDeployment(e.target.value)}
              placeholder="e.g. llama3.1:70b, gpt-4o, qwen2.5-coder:32b" list="models-list" />
            <datalist id="models-list">
              {models.map((m) => <option key={m} value={m} />)}
            </datalist>
            {models.length > 0 && (
              <div className="text-[11px] text-muted mt-1">Discovered: {models.join(", ")}</div>
            )}
          </label>
          <label className="text-sm">API version
            <Input value={apiVersion} onChange={(e) => setApiVersion(e.target.value)}
              placeholder="preview" />
          </label>
          <label className="text-sm">API style
            <select value={apiStyle} onChange={(e) => setApiStyle(e.target.value)}
              className="w-full mt-1 px-3 py-2 rounded-md bg-bg border border-border text-sm">
              <option value="v1">v1 — Azure Foundry Models API</option>
              <option value="local">local — Ollama / vLLM / LM Studio / llama.cpp</option>
              <option value="azure">azure — legacy Azure (deployments + api-version)</option>
            </select>
            <div className="text-[11px] text-muted mt-1">
              {apiStyle === "local"
                ? "Connects to any OpenAI-compatible local server at /v1. No API key needed."
                : apiStyle === "azure"
                ? "Legacy Azure path: /openai/deployments/…?api-version=…"
                : "Azure Foundry v1: /openai/v1/. Auto-detects local endpoints."}
            </div>
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-sm">Context window (tokens)
              <Input value={contextTokens} inputMode="numeric"
                onChange={(e) => setContextTokens(e.target.value.replace(/\D/g, ""))}
                placeholder="auto" />
            </label>
            <label className="text-sm">Parallel requests
              <Input value={concurrency} inputMode="numeric"
                onChange={(e) => setConcurrency(e.target.value.replace(/\D/g, ""))}
                placeholder="4" />
            </label>
            <div className="col-span-2 text-[11px] text-muted -mt-1">
              Local models: set the window your server actually loads (e.g. Ollama
              <code className="mx-1">num_ctx</code>) and 1 parallel request. Blank = auto.
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 mt-4">
          <Button onClick={save}>{fs?.active_profile_name ? `Save to “${fs.active_profile_name}”` : "Save"}</Button>
          <Button variant="ghost" onClick={runTest}>Test connection</Button>
          {msg && <span className="text-sm text-muted">{msg}</span>}
          {test && <span className="text-sm text-muted">{test}</span>}
        </div>
        <p className="text-xs text-muted mt-3">
          Leave the endpoint blank for mock mode (no AI needed).
          For local models: install <a href="https://ollama.com" className="underline" target="_blank" rel="noreferrer">Ollama</a> and
          run <code className="text-xs">ollama pull llama3.1:70b</code>, then set the endpoint
          to <code className="text-xs">http://host.docker.internal:11434</code> (from Docker)
          or <code className="text-xs">http://localhost:11434</code> (native).
        </p>
      </Card>

      <Card className="p-4">
        <h2 className="font-semibold mb-1">Model roles (multi-model pipeline)</h2>
        <p className="text-xs text-muted mb-3">
          Assign different deployments to each stage. Reviewers run in parallel (an
          ensemble); the judge validates their findings, dedupes, and cuts false positives.
          Transport <code>auto</code> picks the Responses API for Codex / o-series models.
          Leave a role blank to fall back to the default deployment above.
        </p>

        <div className="space-y-4">
          <div>
            <div className="text-sm font-medium mb-1">Chat / reasoning</div>
            <RoleEditor role={roles.chat ?? emptyRole()} models={models}
              onChange={(r) => setRoles({ ...roles, chat: r })} />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <div className="text-sm font-medium">Reviewers (vulnerability analysis)</div>
              <Button variant="ghost" onClick={() => setRoles({ ...roles, reviewers: [...roles.reviewers, emptyRole()] })}>
                + Add reviewer
              </Button>
            </div>
            <div className="space-y-2">
              {roles.reviewers.map((r, i) => (
                <RoleEditor key={i} role={r} models={models} removable
                  onRemove={() => setRoles({ ...roles, reviewers: roles.reviewers.filter((_, j) => j !== i) })}
                  onChange={(nr) => setRoles({ ...roles, reviewers: roles.reviewers.map((x, j) => (j === i ? nr : x)) })} />
              ))}
              {roles.reviewers.length === 0 && (
                <div className="text-xs text-muted">No reviewers set — the default deployment is used.</div>
              )}
            </div>
          </div>

          <div>
            <div className="text-sm font-medium mb-1">Judge / validator (optional)</div>
            <RoleEditor role={roles.judge ?? emptyRole()} models={models}
              onChange={(r) => setRoles({ ...roles, judge: r })} />
            <div className="text-[11px] text-muted mt-1">
              Leave blank to skip adjudication and keep raw reviewer findings.
            </div>
          </div>

          <div>
            <div className="text-sm font-medium mb-1">False-positive verifier (optional)</div>
            <RoleEditor role={roles.verifier ?? emptyRole()} models={models}
              onChange={(r) => setRoles({ ...roles, verifier: r })} />
            <div className="text-[11px] text-muted mt-1">
              Runs after the judge and tries to <em>disprove</em> each medium+ finding using
              a wider code window, the function's callers and the routes that reach it.
              Blank = use the judge (or first reviewer). A different model family than the
              reviewers gives the most independent second opinion.
            </div>
          </div>

          <div>
            <div className="text-sm font-medium mb-1">Exploit analyst (optional)</div>
            <RoleEditor role={roles.exploit ?? emptyRole()} models={models}
              onChange={(r) => setRoles({ ...roles, exploit: r })} />
            <div className="text-[11px] text-muted mt-1">
              Runs after the judge on confirmed findings: writes where-to-look, a
              non-destructive proof-of-concept, a risk assessment, and a concrete
              fix for each vulnerability. Leave blank to skip.
            </div>
          </div>
        </div>

        <div className="mt-4"><Button onClick={save}>Save roles</Button></div>
      </Card>

      <Card className="p-4">
        <h2 className="font-semibold mb-1">Static scanners</h2>
        <p className="text-xs text-muted mb-3">
          The high-recall sweep that runs before the AI reviews code. Semgrep runs
          on the worker; SonarQube uploads to a server and pulls issues back. Both
          normalise into the same findings the AI judge then validates.
        </p>

        {/* Semgrep */}
        <div className="flex items-center justify-between py-2 border-b border-border">
          <div>
            <div className="text-sm font-medium">Semgrep</div>
            <div className="text-[11px] text-muted">
              ruleset: <code>{scanners?.semgrep_ruleset || "auto"}</code> · runs locally
            </div>
          </div>
          <Toggle on={!!scanners?.semgrep_enabled}
            onChange={(v) => patchScanners({ semgrep_enabled: v })} />
        </div>

        {/* SonarQube */}
        <div className="py-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">SonarQube</div>
              <div className="text-[11px] text-muted">
                needs a server · start with <code>docker compose --profile sonar up</code>
              </div>
            </div>
            <Toggle on={!!scanners?.sonarqube_enabled}
              onChange={(v) => patchScanners({ sonarqube_enabled: v })} />
          </div>
          {scanners?.sonarqube_enabled && (
            <div className="mt-3 grid grid-cols-2 gap-3">
              <label className="text-sm">Server URL
                <Input value={sonarUrl} onChange={(e) => setSonarUrl(e.target.value)}
                  placeholder="http://sonarqube:9000" />
              </label>
              <label className="text-sm">Token {scanners?.sonarqube_token_set && <span className="text-emerald-400 text-xs">(set)</span>}
                <Input type="password" value={sonarToken} onChange={(e) => setSonarToken(e.target.value)}
                  placeholder={scanners?.sonarqube_token_set ? "•••••• (unchanged)" : "squ_…"} />
              </label>
              <div className="col-span-2 flex items-center gap-3">
                <Button onClick={saveSonar}>Save</Button>
                <Button variant="ghost" onClick={runSonarTest}>Test connection</Button>
                {scanMsg && <span className="text-sm text-muted">{scanMsg}</span>}
                {sonarTest && <span className="text-sm text-muted">{sonarTest}</span>}
              </div>
            </div>
          )}
        </div>
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

function ProfilesCard({ activeId, onActivated }: {
  activeId: string | null; onActivated: () => void;
}) {
  const [profiles, setProfiles] = useState<AiProfile[]>([]);
  const [name, setName] = useState("");
  const [template, setTemplate] = useState("current");
  const [msg, setMsg] = useState("");
  const [tests, setTests] = useState<Record<string, string>>({});

  const reload = () => api.listProfiles().then(setProfiles).catch((e) => setMsg(String(e)));
  useEffect(() => { reload(); }, [activeId]);

  const create = async () => {
    if (!name.trim()) { setMsg("Name the profile first"); return; }
    const t = TEMPLATES[template];
    setMsg("");
    try {
      await api.createProfile({
        name: name.trim(), activate: true,
        from_current: !!t.fromCurrent, settings: t.settings,
      });
      setName("");
      setMsg(template === "azure"
        ? "Created & activated — fill in the endpoint and API key below, then Save."
        : "Created & activated ✓");
      await reload(); onActivated();
    } catch (e) { setMsg(String(e)); }
  };

  const activate = async (p: AiProfile) => {
    try { await api.activateProfile(p.id); setMsg(`Now using “${p.name}”`); await reload(); onActivated(); }
    catch (e) { setMsg(String(e)); }
  };

  const remove = async (p: AiProfile) => {
    if (!confirm(`Delete profile “${p.name}”? Scans pinned to it fall back to the active settings.`)) return;
    try { await api.deleteProfile(p.id); await reload(); onActivated(); }
    catch (e) { setMsg(String(e)); }
  };

  const test = async (p: AiProfile) => {
    setTests((t) => ({ ...t, [p.id]: "testing…" }));
    try {
      const r = await api.testProfile(p.id);
      setTests((t) => ({ ...t, [p.id]: `${r.ok ? "✓" : "✗"} ${r.detail}` }));
    } catch (e) { setTests((t) => ({ ...t, [p.id]: String(e) })); }
  };

  return (
    <Card className="p-4">
      <h2 className="font-semibold mb-1">AI profiles</h2>
      <p className="text-xs text-muted mb-3">
        Save complete AI setups — connection, API key, model roles and tuning — and switch
        between them (e.g. a local Ollama box for sensitive code, Azure for big scans). The
        active profile is the default for new scans; any scan can pin a different one.
      </p>

      <div className="space-y-1.5 mb-4">
        {profiles.map((p) => {
          const reviewers = p.roles?.reviewers?.map((r) => r.deployment).join(", ") || p.deployment;
          return (
            <div key={p.id} className={`px-3 py-2 rounded border text-sm ${p.active ? "border-emerald-500/50 bg-emerald-500/5" : "border-border"}`}>
              <div className="flex items-center gap-2">
                <span className="font-medium">{p.name}</span>
                <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${KIND_STYLE[(p.kind ?? "cloud") as ProfileKind]}`}>
                  {p.kind}
                </span>
                {p.active && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-600/30 text-emerald-300">active</span>}
                <span className="flex-1 truncate text-[11px] text-muted">
                  {p.endpoint || "no endpoint"} · reviewers: {reviewers}
                  {p.concurrency ? ` · ×${p.concurrency}` : ""}
                  {p.context_tokens ? ` · ${Math.round(p.context_tokens / 1024)}K ctx` : ""}
                  {p.api_key_set ? " · key set" : ""}
                </span>
                {!p.active && <Button variant="ghost" onClick={() => activate(p)}>Use</Button>}
                <Button variant="ghost" onClick={() => test(p)}>Test</Button>
                <Button variant="ghost" onClick={() => remove(p)}>✕</Button>
              </div>
              {tests[p.id] && <div className="text-[11px] text-muted mt-1 break-all">{tests[p.id]}</div>}
            </div>
          );
        })}
        {profiles.length === 0 && (
          <div className="text-sm text-muted">
            No profiles yet — save the current settings as one, or start from a template.
          </div>
        )}
      </div>

      <div className="flex items-end gap-2">
        <label className="text-xs flex-1">New profile name
          <Input value={name} onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Local Ollama, Azure prod" />
        </label>
        <label className="text-xs">Start from
          <select value={template} onChange={(e) => setTemplate(e.target.value)}
            className="block mt-1 px-2 py-2 rounded-md bg-bg border border-border text-sm">
            {Object.entries(TEMPLATES).map(([k, t]) => <option key={k} value={k}>{t.label}</option>)}
          </select>
        </label>
        <Button onClick={create}>Create & use</Button>
      </div>
      {msg && <div className="text-xs text-muted mt-2">{msg}</div>}
    </Card>
  );
}

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!on)} type="button"
      className={`relative w-11 h-6 rounded-full transition flex-shrink-0 ${on ? "bg-emerald-600" : "bg-border"}`}>
      <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${on ? "translate-x-5" : ""}`} />
    </button>
  );
}

function RoleEditor({ role, models, onChange, removable, onRemove }: {
  role: ModelRole; models: string[]; onChange: (r: ModelRole) => void;
  removable?: boolean; onRemove?: () => void;
}) {
  // Cloud reasoning models + local ones that think (gpt-oss, Qwen3, DeepSeek-R1…).
  const isReasoning = /codex|^o[134]|gpt-5|gpt-oss|qwen3|deepseek-r1|magistral|qwq|reasoning|thinking/i
    .test(role.deployment);
  return (
    <div className="flex items-end gap-2">
      <label className="text-xs flex-1">deployment
        <Input value={role.deployment} onChange={(e) => onChange({ ...role, deployment: e.target.value })}
          placeholder="e.g. gpt-5-codex" list="role-models-list" />
        <datalist id="role-models-list">{models.map((m) => <option key={m} value={m} />)}</datalist>
      </label>
      <label className="text-xs">transport
        <select value={role.transport} onChange={(e) => onChange({ ...role, transport: e.target.value })}
          className="block mt-1 px-2 py-2 rounded-md bg-bg border border-border text-sm">
          <option value="auto">auto</option><option value="chat">chat</option><option value="responses">responses</option>
        </select>
      </label>
      <label className="text-xs">reasoning
        <select value={role.reasoning_effort ?? ""} disabled={!isReasoning}
          onChange={(e) => onChange({ ...role, reasoning_effort: e.target.value || null })}
          className="block mt-1 px-2 py-2 rounded-md bg-bg border border-border text-sm disabled:opacity-40">
          <option value="">—</option><option value="low">low</option>
          <option value="medium">medium</option><option value="high">high</option>
        </select>
      </label>
      {removable && <Button variant="ghost" onClick={onRemove}>✕</Button>}
    </div>
  );
}
