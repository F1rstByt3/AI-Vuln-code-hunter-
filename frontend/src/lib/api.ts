import type {
  AiProfile, Artifact, ArtifactFile, ChatMessage, Client, Dashboard, DastRun, DastTarget,
  Finding, FindingCode, FoundrySettings, McpServer, Project, Scan, ScanChecks, ScannerSettings,
} from "./types";

const _env_base = (import.meta as any).env?.VITE_API_BASE_URL;
const BASE = _env_base && !_env_base.includes("localhost")
  ? _env_base
  : `http://${window.location.hostname}:8000`;

// In production, swap this for the Entra access token (MSAL). Dev runs AUTH_DISABLED.
function authHeader(): Record<string, string> {
  const t = localStorage.getItem("access_token");
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeader(), ...(init.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 300)}`);
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  base: BASE,
  health: () => req<any>("/health"),

  // clients / projects
  listClients: () => req<Client[]>("/clients"),
  createClient: (b: Partial<Client>) => req<Client>("/clients", { method: "POST", body: JSON.stringify(b) }),
  listProjects: (clientId: string) => req<Project[]>(`/clients/${clientId}/projects`),
  createProject: (clientId: string, b: Partial<Project>) =>
    req<Project>(`/clients/${clientId}/projects`, { method: "POST", body: JSON.stringify(b) }),
  getProject: (id: string) => req<Project>(`/projects/${id}`),
  dashboard: (id: string) => req<Dashboard>(`/projects/${id}/dashboard`),

  // artifacts
  listArtifacts: (projectId: string) => req<Artifact[]>(`/projects/${projectId}/artifacts`),
  createArtifact: (projectId: string, b: { kind: string; source_ref?: string; label?: string }) =>
    req<Artifact>(`/projects/${projectId}/artifacts`, { method: "POST", body: JSON.stringify(b) }),
  listArtifactFiles: (artifactId: string) =>
    req<ArtifactFile[]>(`/artifacts/${artifactId}/files`),

  // scans
  listScans: (projectId: string) => req<Scan[]>(`/projects/${projectId}/scans`),
  createScan: (projectId: string, b: {
    artifact_id: string; scanners: string[]; instructions?: string; model?: string;
    file_paths?: string[]; review_scope?: string; profile_id?: string; checks?: ScanChecks;
  }) =>
    req<Scan>(`/projects/${projectId}/scans`, { method: "POST", body: JSON.stringify(b) }),
  getScan: (id: string) => req<Scan>(`/scans/${id}`),
  cancelScan: (id: string) => req<Scan>(`/scans/${id}/cancel`, { method: "POST" }),
  controlScan: (id: string, action: "pause" | "resume" | "skip" | "cancel") =>
    req<Scan>(`/scans/${id}/control`, { method: "POST", body: JSON.stringify({ action }) }),
  rerunStage: (id: string, stage: string) =>
    req<Scan>(`/scans/${id}/rerun`, { method: "POST", body: JSON.stringify({ stage }) }),
  resumeScan: (id: string) => req<Scan>(`/scans/${id}/resume`, { method: "POST" }),
  scanDiff: (id: string) => req<import("./types").ScanDiff>(`/scans/${id}/diff`),
  scanResumable: (id: string) =>
    req<{ resumable: boolean; completed: Record<string, number> }>(`/scans/${id}/resumable`),
  listFindings: (scanId: string) => req<Finding[]>(`/scans/${scanId}/findings`),
  triageFinding: (id: string, b: { state: string; triage_note?: string }) =>
    req<Finding>(`/findings/${id}/triage`, { method: "POST", body: JSON.stringify(b) }),
  analyzeFinding: (id: string) =>
    req<{ analysis: string; by: string }>(`/findings/${id}/analyze`, { method: "POST" }),
  getFindingCode: (id: string) =>
    req<FindingCode>(`/findings/${id}/code`),

  // chat
  listChat: (scanId: string) => req<ChatMessage[]>(`/scans/${scanId}/chat`),
  postChat: (scanId: string, content: string) =>
    req<ChatMessage>(`/scans/${scanId}/chat`, { method: "POST", body: JSON.stringify({ content }) }),

  // mcp + settings
  listMcp: (projectId?: string) =>
    req<McpServer[]>(`/mcp-servers${projectId ? `?project_id=${projectId}` : ""}`),
  createMcp: (b: Partial<McpServer>, projectId?: string) =>
    req<McpServer>(`/mcp-servers${projectId ? `?project_id=${projectId}` : ""}`, { method: "POST", body: JSON.stringify(b) }),
  deleteMcp: (id: string) => req<void>(`/mcp-servers/${id}`, { method: "DELETE" }),
  getFoundry: () => req<FoundrySettings>("/settings/foundry"),
  updateFoundry: (b: Record<string, any>) => req<FoundrySettings>("/settings/foundry", { method: "PUT", body: JSON.stringify(b) }),
  listModels: () => req<{ models: string[]; mock: boolean }>("/settings/foundry/models"),
  testFoundry: () => req<{ ok: boolean; detail: string; models: string[] }>("/settings/foundry/test", { method: "POST" }),

  // saved AI profiles (local / cloud / mock)
  listProfiles: () => req<AiProfile[]>("/settings/profiles"),
  createProfile: (b: {
    name: string; description?: string; from_current?: boolean; activate?: boolean;
    settings?: Record<string, any>;
  }) => req<AiProfile>("/settings/profiles", { method: "POST", body: JSON.stringify(b) }),
  updateProfile: (id: string, b: Record<string, any>) =>
    req<AiProfile>(`/settings/profiles/${id}`, { method: "PUT", body: JSON.stringify(b) }),
  deleteProfile: (id: string) => req<void>(`/settings/profiles/${id}`, { method: "DELETE" }),
  activateProfile: (id: string) =>
    req<FoundrySettings>(`/settings/profiles/${id}/activate`, { method: "POST" }),
  testProfile: (id: string) =>
    req<{ ok: boolean; detail: string; models: string[] }>(`/settings/profiles/${id}/test`, { method: "POST" }),
  getScanners: () => req<ScannerSettings>("/settings/scanners"),
  updateScanners: (b: Record<string, any>) => req<ScannerSettings>("/settings/scanners", { method: "PUT", body: JSON.stringify(b) }),
  testSonar: () => req<{ ok: boolean; detail: string }>("/settings/scanners/sonar-test", { method: "POST" }),

  // DAST (live access-control confirmation)
  listDastTargets: (projectId: string) => req<DastTarget[]>(`/projects/${projectId}/dast-targets`),
  createDastTarget: (projectId: string, b: Record<string, any>) =>
    req<DastTarget>(`/projects/${projectId}/dast-targets`, { method: "POST", body: JSON.stringify(b) }),
  updateDastTarget: (id: string, b: Record<string, any>) =>
    req<DastTarget>(`/dast-targets/${id}`, { method: "PUT", body: JSON.stringify(b) }),
  deleteDastTarget: (id: string) => req<void>(`/dast-targets/${id}`, { method: "DELETE" }),
  testDastTarget: (id: string) =>
    req<{ ok: boolean; detail: string; roles?: any[] }>(`/dast-targets/${id}/test`, { method: "POST" }),
  addDastCredential: (targetId: string, b: Record<string, any>) =>
    req<any>(`/dast-targets/${targetId}/credentials`, { method: "POST", body: JSON.stringify(b) }),
  deleteDastCredential: (id: string) => req<void>(`/dast-credentials/${id}`, { method: "DELETE" }),
  dastPlan: (scanId: string, b: Record<string, any>) =>
    req<any>(`/scans/${scanId}/dast/plan`, { method: "POST", body: JSON.stringify(b) }),
  launchDast: (scanId: string, b: {
    target_id: string; authorize: boolean; allow_mutating?: boolean; active_scan?: boolean;
    access_control?: boolean; include_paths?: string[]; exclude_paths?: string[];
  }) => req<DastRun>(`/scans/${scanId}/dast`, { method: "POST", body: JSON.stringify(b) }),
  listDastRuns: (scanId: string) => req<DastRun[]>(`/scans/${scanId}/dast-runs`),
  cancelDastRun: (id: string) => req<DastRun>(`/dast-runs/${id}/cancel`, { method: "POST" }),

  // Burp manual testing (Repeater / Intruder)
  burpPackUrl: (scanId: string, o: { base_url?: string; min_risk?: string; with_findings_only?: boolean } = {}) => {
    const q = new URLSearchParams();
    if (o.base_url) q.set("base_url", o.base_url);
    if (o.min_risk) q.set("min_risk", o.min_risk);
    if (o.with_findings_only) q.set("with_findings_only", "true");
    return `${BASE}/api/scans/${scanId}/export/burp-pack?${q}`;
  },
  findingBurpRequest: (findingId: string, base_url?: string) =>
    req<{ raw: string; host: string; port: number; https: boolean; endpoint: string; base_url: string }>(
      `/findings/${findingId}/burp-request${base_url ? `?base_url=${encodeURIComponent(base_url)}` : ""}`),
  burpSend: (b: { mcp_id: string; tool: "repeater" | "intruder"; finding_ids: string[]; base_url?: string }) =>
    req<{ sent: number; errors: string[] }>("/burp/send", { method: "POST", body: JSON.stringify(b) }),

  exportUrl: (scanId: string, format: string) =>
    `${BASE}/api/scans/${scanId}/export/${format}`,

  eventsUrl: (scanId: string) => `${BASE}/api/scans/${scanId}/events`,

  // Resumable upload: init -> PUT each chunk -> complete. Handles 10GB+ files.
  async uploadFile(projectId: string, file: File, onProgress?: (pct: number) => void): Promise<Artifact> {
    const init = await req<{ artifact_id: string; upload_id: string; chunk_bytes: number }>(
      `/projects/${projectId}/uploads`,
      { method: "POST", body: JSON.stringify({ filename: file.name, size_bytes: file.size }) },
    );
    const { artifact_id, upload_id, chunk_bytes } = init;
    const parts: { part: number; etag: string }[] = [];
    const total = Math.ceil(file.size / chunk_bytes) || 1;
    for (let i = 0; i < total; i++) {
      const blob = file.slice(i * chunk_bytes, (i + 1) * chunk_bytes);
      const res = await fetch(
        `${BASE}/api/uploads/${artifact_id}/parts/${i + 1}?upload_id=${encodeURIComponent(upload_id)}`,
        { method: "PUT", headers: { ...authHeader() }, body: blob },
      );
      if (!res.ok) throw new Error(`part ${i + 1} failed: ${res.status}`);
      parts.push(await res.json());
      onProgress?.(Math.round(((i + 1) / total) * 100));
    }
    return req<Artifact>(`/uploads/${artifact_id}/complete`, {
      method: "POST",
      body: JSON.stringify({ upload_id, parts }),
    });
  },
};
