import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import JSZip from "jszip";
import FileTree from "../components/FileTree";
import { Button, Card, Input, Spinner } from "../components/ui";
import { api } from "../lib/api";
import type { Artifact, ArtifactFile, Dashboard, Project, Scan } from "../lib/types";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export default function ProjectPage() {
  const { projectId } = useParams();
  const nav = useNavigate();
  const [project, setProject] = useState<Project>();
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [dash, setDash] = useState<Dashboard>();
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [progress, setProgress] = useState<string | null>(null);
  const [artifactId, setArtifactId] = useState("");
  const [artifactFiles, setArtifactFiles] = useState<ArtifactFile[]>([]);
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [instructions, setInstructions] = useState("");
  const [useSemgrep, setUseSemgrep] = useState(true);
  const [useSonar, setUseSonar] = useState(false);
  const [useAI, setUseAI] = useState(true);
  const [targeted, setTargeted] = useState(false);
  const [err, setErr] = useState("");

  const reload = async () => {
    if (!projectId) return;
    const [p, a, s, d] = await Promise.all([
      api.getProject(projectId), api.listArtifacts(projectId),
      api.listScans(projectId), api.dashboard(projectId),
    ]);
    setProject(p); setArtifacts(a); setScans(s); setDash(d);
    if (a[0] && !artifactId) setArtifactId(a[0].id);
  };
  useEffect(() => { reload().catch((e) => setErr(String(e))); }, [projectId]);
  useEffect(() => { api.listModels().then((m) => { setModels(m.models); }).catch(() => {}); }, []);

  useEffect(() => {
    if (!artifactId) { setArtifactFiles([]); setSelectedPaths([]); return; }
    setLoadingFiles(true);
    api.listArtifactFiles(artifactId)
      .then((f) => { setArtifactFiles(f); setSelectedPaths([]); })
      .catch(() => setArtifactFiles([]))
      .finally(() => setLoadingFiles(false));
  }, [artifactId]);

  const folderRef = useRef<HTMLInputElement>(null);

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files?.length || !projectId) return;
    const total = files.length;
    try {
      for (let i = 0; i < total; i++) {
        const file = files[i];
        setProgress(`Uploading ${file.name} (${i + 1}/${total})…`);
        await api.uploadFile(projectId, file, (pct) =>
          setProgress(`Uploading ${file.name} (${i + 1}/${total})… ${pct}%`));
      }
      await reload();
    } catch (e) { setErr(String(e)); }
    finally { setProgress(null); e.target.value = ""; }
  };

  const onFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files?.length || !projectId) return;
    try {
      setProgress(`Zipping ${files.length} files from folder…`);
      const zip = new JSZip();
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const path = (f as any).webkitRelativePath || f.name;
        zip.file(path, f);
      }
      const blob = await zip.generateAsync({ type: "blob", compression: "DEFLATE" });
      const firstPath = (files[0] as any).webkitRelativePath || "";
      const folderName = firstPath.split("/")[0] || "folder";
      const zipFile = new File([blob], `${folderName}.zip`, { type: "application/zip" });
      setProgress(`Uploading ${zipFile.name} (${(zipFile.size / 1024 / 1024).toFixed(1)} MB)…`);
      await api.uploadFile(projectId, zipFile, (pct) =>
        setProgress(`Uploading ${zipFile.name}… ${pct}%`));
      await reload();
    } catch (e) { setErr(String(e)); }
    finally { setProgress(null); e.target.value = ""; }
  };

  const addGit = async () => {
    if (!projectId || !gitUrl.trim()) return;
    await api.createArtifact(projectId, { kind: "git", source_ref: gitUrl.trim() });
    setGitUrl(""); reload();
  };

  const startScan = async () => {
    if (!projectId || !artifactId) return;
    const scanners: string[] = ["mcp"];  // configured MCP agents always contribute
    if (useSemgrep) scanners.push("semgrep");
    if (useSonar) scanners.push("sonarqube");
    if (useAI) scanners.push("ai");
    if (scanners.length === 1) { setErr("Select at least one scanner"); return; }
    setErr("");
    const scan = await api.createScan(projectId, {
      artifact_id: artifactId, scanners, instructions,
      model: model.trim() || undefined,
      file_paths: selectedPaths.length > 0 ? selectedPaths : undefined,
      review_scope: targeted ? "targeted" : "full",
    });
    nav(`/scans/${scan.id}`);
  };

  return (
    <div>
      <button onClick={() => nav("/")} className="text-sm text-muted hover:text-slate-200 mb-2">← Clients</button>
      <h1 className="text-2xl font-bold">{project?.name || "Project"}</h1>
      <p className="text-muted text-sm mb-6">{project?.description}</p>
      {err && <div className="text-red-400 text-sm mb-4">{err}</div>}

      {dash && <DashboardPanel d={dash} />}

      <div className="grid grid-cols-2 gap-6 mt-6">
        <Card className="p-4">
          <h2 className="font-semibold mb-3">Code (artifacts)</h2>
          <div className="mb-3">
            <span className="text-sm text-muted block mb-1">Upload archives / files (resumable, 10GB+)</span>
            <div className="flex gap-2 items-center">
              <label className="px-3 py-1.5 rounded-md text-sm font-medium bg-emerald-600 hover:bg-emerald-700 cursor-pointer transition">
                Files
                <input type="file" multiple onChange={onUpload} className="hidden" />
              </label>
              <label className="px-3 py-1.5 rounded-md text-sm font-medium bg-border hover:bg-border/80 cursor-pointer transition">
                Folder
                <input ref={folderRef} type="file" onChange={onFolderUpload} className="hidden"
                  {...{ webkitdirectory: "", directory: "" } as any} />
              </label>
              <span className="text-[11px] text-muted">zip, tar.gz, or select a folder</span>
            </div>
            {progress !== null && <div className="text-xs text-emerald-400 mt-1">{progress}</div>}
          </div>
          <div className="flex gap-2 mb-4">
            <Input placeholder="git url#ref" value={gitUrl} onChange={(e) => setGitUrl(e.target.value)} />
            <Button variant="ghost" onClick={addGit}>Link git</Button>
          </div>
          <div className="space-y-1 max-h-48 overflow-auto">
            {artifacts.map((a) => (
              <label key={a.id} className="flex items-center gap-2 px-2 py-1 rounded hover:bg-border text-sm">
                <input type="radio" name="artifact" checked={artifactId === a.id} onChange={() => setArtifactId(a.id)} />
                <span className="flex-1 truncate">{a.label || a.source_ref || a.id}</span>
                <span className="text-xs text-muted">{a.kind} · {a.analyzable_count || 0} files</span>
              </label>
            ))}
            {artifacts.length === 0 && <div className="text-muted text-sm">No code yet.</div>}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="font-semibold mb-3">Start a review</h2>
          <div className="mb-3">
            <span className="text-sm text-muted">Scanners</span>
            <div className="flex flex-wrap gap-3 mt-1">
              <label className="flex items-center gap-1.5 text-sm">
                <input type="checkbox" checked={useSemgrep} onChange={(e) => setUseSemgrep(e.target.checked)} />
                Semgrep
              </label>
              <label className="flex items-center gap-1.5 text-sm">
                <input type="checkbox" checked={useSonar} onChange={(e) => setUseSonar(e.target.checked)} />
                SonarQube
              </label>
              <label className="flex items-center gap-1.5 text-sm">
                <input type="checkbox" checked={useAI} onChange={(e) => setUseAI(e.target.checked)} />
                AI review
              </label>
            </div>
            <div className="text-[11px] text-muted mt-1">
              {useAI
                ? "AI review triages scanner candidates and hunts for more (reviewers → judge → exploit analyst)."
                : "Static-only: scanner findings are saved directly, no AI triage."}
              {" "}SonarQube requires it to be enabled in Settings.
            </div>
            {useAI && (
              <div className="mt-2">
                <label className="flex items-center gap-1.5 text-sm">
                  <input type="checkbox" checked={targeted}
                    onChange={(e) => setTargeted(e.target.checked)} />
                  Targeted review <span className="text-[11px] text-emerald-400">(much cheaper)</span>
                </label>
                <div className="text-[11px] text-muted mt-0.5">
                  {targeted
                    ? "Only files flagged by a scanner or exposing an endpoint go to the LLM — slashes token cost, but may miss vulns the scanners didn't flag."
                    : "Full review reads every source file (most thorough, most expensive)."}
                </div>
              </div>
            )}
          </div>
          <label className="text-sm text-muted">Reviewer model override (optional)
            <Input value={model} onChange={(e) => setModel(e.target.value)}
              placeholder="Leave blank to use Settings roles" list="project-models-list"
              className="mt-1 mb-3" />
            <datalist id="project-models-list">
              {models.map((m) => <option key={m} value={m} />)}
            </datalist>
            {models.length > 0 && (
              <div className="text-[11px] text-muted">Available: {models.join(", ")}</div>
            )}
          </label>
          <label className="text-sm text-muted">Instructions for the agent (optional)</label>
          <textarea value={instructions} onChange={(e) => setInstructions(e.target.value)}
            placeholder="e.g. focus on auth & the payments module; ignore tests"
            className="w-full mt-1 mb-3 px-3 py-2 rounded-md bg-bg border border-border text-sm h-20" />
          <Button onClick={startScan} disabled={!artifactId}>▶ Run analysis</Button>

          <h3 className="font-semibold mt-6 mb-2 text-sm">Recent scans</h3>
          <div className="space-y-1 max-h-40 overflow-auto">
            {scans.map((s) => (
              <button key={s.id} onClick={() => nav(`/scans/${s.id}`)}
                className="w-full flex justify-between px-2 py-1.5 rounded hover:bg-border text-sm">
                <span>{new Date(s.created_at).toLocaleString()}</span>
                <span className="text-xs text-muted">{s.status}</span>
              </button>
            ))}
            {scans.length === 0 && <div className="text-muted text-sm">No scans yet.</div>}
          </div>
        </Card>
      </div>

      {artifactId && (
        <Card className="p-4 mt-6">
          <h2 className="font-semibold mb-3">
            Scope: select files & folders
            {selectedPaths.length > 0 && (
              <span className="text-xs font-normal text-emerald-400 ml-2">
                {selectedPaths.length} selected
              </span>
            )}
            {selectedPaths.length === 0 && (
              <span className="text-xs font-normal text-muted ml-2">
                all files (click to narrow scope)
              </span>
            )}
          </h2>
          {loadingFiles ? (
            <div className="flex items-center gap-2 text-muted text-sm p-4"><Spinner /> Loading file tree...</div>
          ) : (
            <FileTree files={artifactFiles} selectedPaths={selectedPaths} onSelectionChange={setSelectedPaths} />
          )}
        </Card>
      )}
    </div>
  );
}

function DashboardPanel({ d }: { d: Dashboard }) {
  const [showEndpoints, setShowEndpoints] = useState(false);
  const endpoints = d.endpoints || [];
  const unauthEndpoints = endpoints.filter((e) => e.auth_hints.length === 0);

  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold">Vulnerability dashboard</h2>
        <div className="text-right">
          <div className="text-3xl font-bold text-emerald-400">{d.risk_score}</div>
          <div className="text-xs text-muted">risk score</div>
        </div>
      </div>
      <div className="grid grid-cols-5 gap-2 mb-4">
        {SEV_ORDER.map((s) => (
          <div key={s} className="text-center rounded-md border border-border py-2">
            <div className="text-xl font-bold">{d.by_severity?.[s] ?? 0}</div>
            <div className="text-[11px] uppercase text-muted">{s}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-4 text-sm">
        <Stat label="Total findings" value={d.total_findings} />
        <Stat label="Open" value={d.open_findings} />
        <Stat label="Needs human review" value={d.needs_review} highlight />
      </div>
      {d.top_files.length > 0 && (
        <div className="mt-4">
          <div className="text-xs text-muted mb-1">Hotspot files</div>
          {d.top_files.slice(0, 5).map((f) => (
            <div key={f.path} className="flex justify-between text-xs py-0.5">
              <span className="truncate">{f.path}</span><span className="text-muted">{f.count}</span>
            </div>
          ))}
        </div>
      )}
      {endpoints.length > 0 && (
        <div className="mt-4">
          <div className="flex items-center justify-between mb-1">
            <button onClick={() => setShowEndpoints((o) => !o)}
              className="text-xs text-muted hover:text-slate-200 flex items-center gap-1">
              <span>{showEndpoints ? "▼" : "▶"}</span>
              Discovered endpoints ({endpoints.length})
              {unauthEndpoints.length > 0 && (
                <span className="text-amber-400 ml-1">
                  {unauthEndpoints.length} without auth
                </span>
              )}
            </button>
          </div>
          {showEndpoints && (
            <div className="max-h-64 overflow-auto border border-border rounded-md bg-bg">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-muted border-b border-border">
                    <th className="text-left px-2 py-1">Method</th>
                    <th className="text-left px-2 py-1">Path</th>
                    <th className="text-left px-2 py-1">File</th>
                    <th className="text-left px-2 py-1">Auth</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep, i) => (
                    <tr key={i} className={`border-b border-border/50 ${ep.auth_hints.length === 0 ? "text-amber-300/80" : ""}`}>
                      <td className="px-2 py-0.5 font-mono">{ep.method}</td>
                      <td className="px-2 py-0.5 font-mono">{ep.path}</td>
                      <td className="px-2 py-0.5 text-muted">{ep.file_path}:{ep.line}</td>
                      <td className="px-2 py-0.5">
                        {ep.auth_hints.length > 0
                          ? <span className="text-emerald-400">{ep.auth_hints.join(", ")}</span>
                          : <span className="text-amber-400">none detected</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function Stat({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className={`text-2xl font-bold ${highlight && value > 0 ? "text-fuchsia-300" : ""}`}>{value}</div>
      <div className="text-xs text-muted">{label}</div>
    </div>
  );
}
