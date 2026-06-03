import type {
  Artifact, ArtifactFile, ChatMessage, Client, Dashboard, Finding,
  FoundrySettings, McpServer, Project, Scan,
} from "./types";

const BASE = (import.meta as any).env?.VITE_API_BASE_URL || "http://localhost:8000";

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
  createScan: (projectId: string, b: { artifact_id: string; scanners: string[]; instructions?: string; model?: string; file_paths?: string[] }) =>
    req<Scan>(`/projects/${projectId}/scans`, { method: "POST", body: JSON.stringify(b) }),
  getScan: (id: string) => req<Scan>(`/scans/${id}`),
  cancelScan: (id: string) => req<Scan>(`/scans/${id}/cancel`, { method: "POST" }),
  listFindings: (scanId: string) => req<Finding[]>(`/scans/${scanId}/findings`),
  triageFinding: (id: string, b: { state: string; triage_note?: string }) =>
    req<Finding>(`/findings/${id}/triage`, { method: "POST", body: JSON.stringify(b) }),

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
