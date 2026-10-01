import { useEffect, useState } from "react";
import { Button, Card, Input, PageHeader, Tabs } from "../components/ui";
import { api } from "../lib/api";
import type {
  AiProfile, FoundrySettings, McpServer, ModelRole, ModelRoles, ProfileKind, ScannerSettings,
} from "../lib/types";

const emptyRole = (deployment = ""): ModelRole => ({ deployment, transport: "auto", reasoning_effort: null });

const NO_ROLES = { chat: null, reviewers: [], judge: null, exploit: null, verifier: null };

const TEMPLATES: Record<string, { label: string; fromCurrent?: boolean; settings?: Record<string, any> }> = {
  current: { label: "Current settings (incl. API key)", fromCurrent: true },
  ollama: {
    label: "Local · Ollama",
    settings: { endpoint: "http://host.docker.internal:11434", api_style: "local", api_version: "",
      deployment: "qwen3-coder:30b", context_tokens: 32768, concurrency: 1, roles: NO_ROLES },
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

const selectCls = "w-full mt-1 px-3 py-2 rounded-lg bg-bg border border-border text-sm outline-none focus:border-accent";

export default function SettingsPage() {
  const [tab, setTab] = useState("connection");
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
    try {
      const r = await api.testFoundry();
      setTest(`${r.ok ? "✓" : "✗"} ${r.detail}${r.models.length ? ` · models: ${r.models.join(", ")}` : ""}`);
      if (r.models.length) setModels(r.models);
    } catch (e) { setTest(String(e)); }
  };

  const saveLabel = fs?.active_profile_name ? `Save to “${fs.active_profile_name}”` : "Save";

  return (
    <div>
      <PageHeader
        title="Settings"
        subtitle="Configure the AI, scanners, and integrations used by scans."
        actions={fs && (
          <span className={`text-xs px-2.5 py-1 rounded-full border ${fs.mock_mode ? "border-amber-500/40 text-amber-300" : "border-emerald-500/40 text-emerald-300"}`}>
            {fs.mock_mode ? "MOCK MODE" : `${fs.kind ?? "connected"} · ${fs.auth_mode}`}
            {fs.active_profile_name ? ` · ${fs.active_profile_name}` : ""}
          </span>
        )}
      />

      <Tabs active={tab} onChange={setTab} tabs={[
        { key: "connection", label: "AI Connection" },
        { key: "roles", label: "Model roles" },
        { key: "profiles", label: "Profiles" },
        { key: "scanners", label: "Scanners" },
        { key: "integrations", label: "Integrations", badge: mcp.length || undefined },
      ]} />

      {tab === "connection" && (
        <Card className="p-5">
          <div className="text-[11px] text-muted mb-4">
            {fs?.active_profile_name
              ? <>Editing profile <span className="text-slate-200 font-medium">{fs.active_profile_name}</span> — saving updates it.</>
              : "Active settings (not saved as a profile)."}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <label className="text-sm">Endpoint URL
              <Input value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
                placeholder="http://host.docker.internal:11434 or https://my-foundry…" />
            </label>
            <label className="text-sm">API key {fs?.api_key_set && <span className="text-emerald-400 text-xs">(set)</span>}
              <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                placeholder={fs?.api_key_set ? "•••••• (unchanged)" : "paste key — not needed for local"} />
            </label>
            <label className="text-sm">Model / deployment name
              <Input value={deployment} onChange={(e) => setDeployment(e.target.value)}
                placeholder="e.g. qwen3-coder:30b, gpt-5-codex" list="models-list" />
              <datalist id="models-list">{models.map((m) => <option key={m} value={m} />)}</datalist>
              {models.length > 0 && <div className="text-[11px] text-muted mt-1">Discovered: {models.join(", ")}</div>}
            </label>
            <label className="text-sm">API version
              <Input value={apiVersion} onChange={(e) => setApiVersion(e.target.value)} placeholder="preview" />
            </label>
            <label className="text-sm">API style
              <select value={apiStyle} onChange={(e) => setApiStyle(e.target.value)} className={selectCls}>
                <option value="v1">v1 — Azure Foundry Models API</option>
                <option value="local">local — Ollama / vLLM / LM Studio / llama.cpp</option>
                <option value="azure">azure — legacy Azure (deployments + api-version)</option>
              </select>
              <div className="text-[11px] text-muted mt-1">
                {apiStyle === "local" ? "Any OpenAI-compatible local server at /v1. No API key needed."
                  : apiStyle === "azure" ? "Legacy Azure path: /openai/deployments/…?api-version=…"
                  : "Azure Foundry v1: /openai/v1/. Auto-detects local endpoints."}
              </div>
            </label>
            <div className="grid grid-cols-2 gap-4">
              <label className="text-sm">Context window
                <Input value={contextTokens} inputMode="numeric"
                  onChange={(e) => setContextTokens(e.target.value.replace(/\D/g, ""))} placeholder="auto" />
              </label>
              <label className="text-sm">Parallel requests
                <Input value={concurrency} inputMode="numeric"
                  onChange={(e) => setConcurrency(e.target.value.replace(/\D/g, ""))} placeholder="4" />
              </label>
            </div>
          </div>
          <p className="text-[11px] text-muted mt-2">
            Local models: set the context window your server actually loads (Ollama <code className="mx-0.5">OLLAMA_CONTEXT_LENGTH</code>)
            and 1 parallel request. Leave the endpoint blank for mock mode.
          </p>
          <div className="flex items-center gap-3 mt-5">
            <Button onClick={save}>{saveLabel}</Button>
            <Button variant="ghost" onClick={runTest}>Test connection</Button>
            {msg && <span className="text-sm text-muted">{msg}</span>}
            {test && <span className="text-sm text-muted break-all">{test}</span>}
          </div>
        </Card>
      )}

      {tab === "roles" && (
        <Card className="p-5">
          <p className="text-xs text-muted mb-4">
            Assign models to each stage. Reviewers run in parallel (an ensemble); the judge
            dedupes and cuts false positives; the verifier tries to disprove each finding;
            the exploit analyst writes PoCs. Leave a role blank to use the model above.
          </p>
          <div className="space-y-5">
            <RoleBlock title="Chat / reasoning">
              <RoleEditor role={roles.chat ?? emptyRole()} models={models}
                onChange={(r) => setRoles({ ...roles, chat: r })} />
            </RoleBlock>
            <RoleBlock title="Reviewers (vulnerability analysis)"
              action={<Button variant="ghost" onClick={() => setRoles({ ...roles, reviewers: [...roles.reviewers, emptyRole()] })}>+ Add reviewer</Button>}>
              <div className="space-y-2">
                {roles.reviewers.map((r, i) => (
                  <RoleEditor key={i} role={r} models={models} removable
                    onRemove={() => setRoles({ ...roles, reviewers: roles.reviewers.filter((_, j) => j !== i) })}
                    onChange={(nr) => setRoles({ ...roles, reviewers: roles.reviewers.map((x, j) => (j === i ? nr : x)) })} />
                ))}
                {roles.reviewers.length === 0 && <div className="text-xs text-muted">No reviewers set — the model above is used.</div>}
              </div>
            </RoleBlock>
            <RoleBlock title="Judge / validator (optional)" hint="Blank = skip adjudication, keep raw reviewer findings.">
              <RoleEditor role={roles.judge ?? emptyRole()} models={models} onChange={(r) => setRoles({ ...roles, judge: r })} />
            </RoleBlock>
            <RoleBlock title="False-positive verifier (optional)" hint="Tries to disprove each medium+ finding. A different model family gives the most independent second opinion.">
              <RoleEditor role={roles.verifier ?? emptyRole()} models={models} onChange={(r) => setRoles({ ...roles, verifier: r })} />
            </RoleBlock>
            <RoleBlock title="Exploit analyst (optional)" hint="On confirmed findings: writes where-to-look, a non-destructive PoC, risk, and a fix.">
              <RoleEditor role={roles.exploit ?? emptyRole()} models={models} onChange={(r) => setRoles({ ...roles, exploit: r })} />
            </RoleBlock>
          </div>
          <div className="mt-5 flex items-center gap-3">
            <Button onClick={save}>Save roles</Button>
            {msg && <span className="text-sm text-muted">{msg}</span>}
          </div>
        </Card>
      )}

      {tab === "profiles" && (
        <ProfilesCard activeId={fs?.active_profile_id ?? null}
          onActivated={() => load().catch((e) => setMsg(String(e)))} />
      )}

      {tab === "scanners" && (
        <Card className="p-5">
          <p className="text-xs text-muted mb-4">
            The high-recall sweep before the AI reviews code. Semgrep runs on the worker;
            SonarQube uploads to a server and pulls issues back. Both normalise into the
            same findings the AI judge then validates.
          </p>
          <div className="flex items-center justify-between py-3 border-b border-border">
            <div>
              <div className="text-sm font-medium">Semgrep</div>
              <div className="text-[11px] text-muted">ruleset: <code>{scanners?.semgrep_ruleset || "auto"}</code> · runs locally</div>
            </div>
            <Toggle on={!!scanners?.semgrep_enabled} onChange={(v) => patchScanners({ semgrep_enabled: v })} />
          </div>
          <div className="py-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">SonarQube</div>
                <div className="text-[11px] text-muted">needs a server · <code>docker compose --profile sonar up</code></div>
              </div>
              <Toggle on={!!scanners?.sonarqube_enabled} onChange={(v) => patchScanners({ sonarqube_enabled: v })} />
            </div>
            {scanners?.sonarqube_enabled && (
              <div className="mt-3 grid grid-cols-2 gap-4">
                <label className="text-sm">Server URL
                  <Input value={sonarUrl} onChange={(e) => setSonarUrl(e.target.value)} placeholder="http://sonarqube:9000" />
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
      )}

      {tab === "integrations" && (
        <IntegrationsTab mcp={mcp} reload={() => api.listMcp().then(setMcp)} />
      )}
    </div>
  );
}

function RoleBlock({ title, hint, action, children }: {
  title: string; hint?: string; action?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <div className="text-sm font-medium">{title}</div>
        {action}
      </div>
      {children}
      {hint && <div className="text-[11px] text-muted mt-1">{hint}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- Integrations
function IntegrationsTab({ mcp, reload }: { mcp: McpServer[]; reload: () => Promise<any> }) {
  const [newMcp, setNewMcp] = useState({ name: "", kind: "custom", transport: "sse", url: "" });
  const [msg, setMsg] = useState("");

  const add = async () => {
    if (!newMcp.name || !newMcp.url) { setMsg("name and url required"); return; }
    setMsg("");
    try {
      await api.createMcp(newMcp);
      setNewMcp({ name: "", kind: "custom", transport: "sse", url: "" });
      await reload();
    } catch (e) { setMsg(String(e)); }
  };
  const burpPreset = () => setNewMcp({ name: "burp", kind: "burp", transport: "sse",
    url: "http://host.docker.internal:9876/sse" });

  const burp = mcp.find((m) => m.kind === "burp");

  return (
    <div className="space-y-6">
      <Card className="p-5">
        <h2 className="font-semibold mb-1">Burp Suite</h2>
        <p className="text-xs text-muted mb-3">
          Install Burp's <b>MCP Server</b> extension (Burp 2025.x; Pro for active scanning), note
          its URL, then register it below. Once registered you can:
        </p>
        <ul className="text-xs text-slate-300 mb-3 space-y-1 list-disc pl-5">
          <li><b>Manual testing</b> — send any finding with an endpoint straight to <b>Repeater</b> or
            <b> Intruder</b> (object ids pre-marked with §) from the scan page, one at a time or in bulk.</li>
          <li><b>Live DAST</b> — seed the authenticated request surface into Burp and pull its
            active-scan issues back as findings.</li>
        </ul>
        <p className="text-[11px] text-muted mb-3">
          No Burp MCP? Use <b>Copy for Burp</b> on a finding or the <b>Burp pack (Intruder)</b> download
          on the scan page. Requests carry a placeholder Authorization header — stored DAST
          credentials never leave the app.
        </p>
        {burp ? (
          <McpRow m={burp} reload={reload} />
        ) : (
          <Button variant="accent" onClick={burpPreset}>+ Add Burp (fills the form below)</Button>
        )}
      </Card>

      <Card className="p-5">
        <h2 className="font-semibold mb-1">MCP servers</h2>
        <p className="text-xs text-muted mb-3">
          Register MCP servers the platform can call — Burp, extra Semgrep/SonarQube bridges,
          or custom scanners. Burp is used by DAST; the others contribute static candidates.
        </p>
        <div className="grid grid-cols-[1fr_8rem_7rem_1.4fr_auto] gap-2 mb-3 items-end">
          <label className="text-[11px]">name
            <Input value={newMcp.name} onChange={(e) => setNewMcp({ ...newMcp, name: e.target.value })} placeholder="burp" />
          </label>
          <label className="text-[11px]">kind
            <select value={newMcp.kind} onChange={(e) => setNewMcp({ ...newMcp, kind: e.target.value })} className={selectCls}>
              <option>burp</option><option>semgrep</option><option>sonarqube</option><option>custom</option>
            </select>
          </label>
          <label className="text-[11px]">transport
            <select value={newMcp.transport} onChange={(e) => setNewMcp({ ...newMcp, transport: e.target.value })} className={selectCls}>
              <option>sse</option><option>http</option><option>stdio</option>
            </select>
          </label>
          <label className="text-[11px]">url
            <Input value={newMcp.url} onChange={(e) => setNewMcp({ ...newMcp, url: e.target.value })}
              placeholder="http://host.docker.internal:9876/sse" />
          </label>
          <Button onClick={add}>Add</Button>
        </div>
        {msg && <div className="text-[11px] text-rose-300 mb-2">{msg}</div>}
        <div className="space-y-1.5">
          {mcp.map((m) => <McpRow key={m.id} m={m} reload={reload} />)}
          {mcp.length === 0 && <div className="text-muted text-sm">No MCP servers registered.</div>}
        </div>
      </Card>
    </div>
  );
}

const BURP_READY_LABEL: Record<string, string> = {
  active_scan: "active scan", active_scan_issues: "scan + read issues",
  manual_repeater: "→ Repeater", manual_intruder: "→ Intruder",
};

/** One registered MCP server with a deployment health-check ("Test"). */
function McpRow({ m, reload }: { m: McpServer; reload: () => Promise<any> }) {
  const [res, setRes] = useState<Awaited<ReturnType<typeof api.testMcp>> | null>(null);
  const [testing, setTesting] = useState(false);
  const runTest = async () => {
    setTesting(true); setRes(null);
    try { setRes(await api.testMcp(m.id)); }
    catch (e) { setRes({ ok: false, detail: String(e) }); }
    finally { setTesting(false); }
  };
  return (
    <div className="px-3 py-2 rounded-lg border border-border text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 min-w-0">
          <span className="font-medium">{m.name}</span>
          <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-border/70 text-slate-300">{m.kind}</span>
          <span className="text-muted text-[11px] truncate">{m.transport} · {m.url}</span>
        </span>
        <div className="flex items-center gap-2 shrink-0">
          {res && <span className={res.ok ? "text-emerald-400 text-xs" : "text-rose-300 text-xs"}>
            {res.ok ? "✓" : "✗"} {res.detail}</span>}
          <Button variant="ghost" onClick={runTest} disabled={testing}>{testing ? "testing…" : "Test"}</Button>
          <Button variant="ghost" onClick={() => api.deleteMcp(m.id).then(reload)}>Remove</Button>
        </div>
      </div>
      {res?.ok && res.ready && (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {Object.entries(res.ready).map(([k, on]) => (
            <span key={k} className={`text-[10px] px-1.5 py-0.5 rounded border ${
              on ? "border-emerald-500/40 text-emerald-300" : "border-border text-muted"}`}>
              {on ? "✓" : "—"} {BURP_READY_LABEL[k] || k}
            </span>
          ))}
        </div>
      )}
      {res?.ok && !res.ready && (res.tools?.length ?? 0) > 0 && (
        <div className="mt-1 text-[11px] text-muted truncate">tools: {res.tools!.join(", ")}</div>
      )}
      {res?.warn && <div className="mt-1 text-[11px] text-amber-300">{res.warn}</div>}
      {res?.note && <div className="mt-1 text-[11px] text-muted">{res.note}</div>}
      {res && !res.ok && res.hint && <div className="mt-1 text-[11px] text-amber-300">{res.hint}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- Profiles
function ProfilesCard({ activeId, onActivated }: { activeId: string | null; onActivated: () => void }) {
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
      await api.createProfile({ name: name.trim(), activate: true, from_current: !!t.fromCurrent, settings: t.settings });
      setName("");
      setMsg(template === "azure" ? "Created & activated — fill in the endpoint and API key on the Connection tab, then Save." : "Created & activated ✓");
      await reload(); onActivated();
    } catch (e) { setMsg(String(e)); }
  };
  const activate = async (p: AiProfile) => {
    try { await api.activateProfile(p.id); setMsg(`Now using “${p.name}”`); await reload(); onActivated(); }
    catch (e) { setMsg(String(e)); }
  };
  const remove = async (p: AiProfile) => {
    if (!confirm(`Delete profile “${p.name}”?`)) return;
    try { await api.deleteProfile(p.id); await reload(); onActivated(); } catch (e) { setMsg(String(e)); }
  };
  const test = async (p: AiProfile) => {
    setTests((t) => ({ ...t, [p.id]: "testing…" }));
    try { const r = await api.testProfile(p.id); setTests((t) => ({ ...t, [p.id]: `${r.ok ? "✓" : "✗"} ${r.detail}` })); }
    catch (e) { setTests((t) => ({ ...t, [p.id]: String(e) })); }
  };

  return (
    <Card className="p-5">
      <p className="text-xs text-muted mb-4">
        Save complete AI setups — connection, API key, model roles and tuning — and switch
        between them (a local Ollama box for sensitive code, Azure for big scans). The active
        profile is the default for new scans; any scan can pin a different one.
      </p>
      <div className="space-y-2 mb-5">
        {profiles.map((p) => {
          const reviewers = p.roles?.reviewers?.map((r) => r.deployment).join(", ") || p.deployment;
          return (
            <div key={p.id} className={`px-3 py-2.5 rounded-lg border text-sm ${p.active ? "border-emerald-500/50 bg-emerald-500/5" : "border-border"}`}>
              <div className="flex items-center gap-2">
                <span className="font-medium">{p.name}</span>
                <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${KIND_STYLE[(p.kind ?? "cloud") as ProfileKind]}`}>{p.kind}</span>
                {p.active && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-600/30 text-emerald-300">active</span>}
                <span className="flex-1 truncate text-[11px] text-muted">
                  {p.endpoint || "no endpoint"} · {reviewers}
                  {p.concurrency ? ` · ×${p.concurrency}` : ""}{p.context_tokens ? ` · ${Math.round(p.context_tokens / 1024)}K ctx` : ""}{p.api_key_set ? " · key set" : ""}
                </span>
                {!p.active && <Button variant="ghost" onClick={() => activate(p)}>Use</Button>}
                <Button variant="ghost" onClick={() => test(p)}>Test</Button>
                <Button variant="ghost" onClick={() => remove(p)}>✕</Button>
              </div>
              {tests[p.id] && <div className="text-[11px] text-muted mt-1 break-all">{tests[p.id]}</div>}
            </div>
          );
        })}
        {profiles.length === 0 && <div className="text-sm text-muted">No profiles yet — save the current settings, or start from a template.</div>}
      </div>
      <div className="flex items-end gap-2">
        <label className="text-xs flex-1">New profile name
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Local Ollama, Azure prod" />
        </label>
        <label className="text-xs">Start from
          <select value={template} onChange={(e) => setTemplate(e.target.value)} className={selectCls}>
            {Object.entries(TEMPLATES).map(([k, t]) => <option key={k} value={k}>{t.label}</option>)}
          </select>
        </label>
        <Button variant="accent" onClick={create}>Create &amp; use</Button>
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
  const isReasoning = /codex|^o[134]|gpt-5|gpt-oss|qwen3|deepseek-r1|magistral|qwq|reasoning|thinking/i.test(role.deployment);
  return (
    <div className="flex items-end gap-2">
      <label className="text-xs flex-1">deployment
        <Input value={role.deployment} onChange={(e) => onChange({ ...role, deployment: e.target.value })}
          placeholder="e.g. qwen3-coder:30b" list="role-models-list" />
        <datalist id="role-models-list">{models.map((m) => <option key={m} value={m} />)}</datalist>
      </label>
      <label className="text-xs">transport
        <select value={role.transport} onChange={(e) => onChange({ ...role, transport: e.target.value })} className={selectCls}>
          <option value="auto">auto</option><option value="chat">chat</option><option value="responses">responses</option>
        </select>
      </label>
      <label className="text-xs">reasoning
        <select value={role.reasoning_effort ?? ""} disabled={!isReasoning}
          onChange={(e) => onChange({ ...role, reasoning_effort: e.target.value || null })}
          className={`${selectCls} disabled:opacity-40`}>
          <option value="">—</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option>
        </select>
      </label>
      {removable && <Button variant="ghost" onClick={onRemove}>✕</Button>}
    </div>
  );
}
