import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { api } from "../lib/api";
import type { Client, Project } from "../lib/types";

export default function ClientsPage() {
  const [clients, setClients] = useState<Client[]>([]);
  const [projects, setProjects] = useState<Record<string, Project[]>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [newClient, setNewClient] = useState("");
  const [newProject, setNewProject] = useState("");
  const [err, setErr] = useState("");
  const nav = useNavigate();

  const load = () => api.listClients().then(setClients).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);

  const openClient = async (id: string) => {
    setSelected(id);
    const list = await api.listProjects(id);
    setProjects((p) => ({ ...p, [id]: list }));
  };

  const addClient = async () => {
    if (!newClient.trim()) return;
    await api.createClient({ name: newClient.trim() });
    setNewClient(""); load();
  };

  const addProject = async () => {
    if (!selected || !newProject.trim()) return;
    await api.createProject(selected, { name: newProject.trim() });
    setNewProject(""); openClient(selected);
  };

  const removeClient = async (c: Client) => {
    if (!confirm(`Delete client “${c.name}” and ALL its projects, scans, findings and `
      + `uploaded code? This cannot be undone.`)) return;
    try {
      await api.deleteClient(c.id);
      if (selected === c.id) setSelected(null);
      load();
    } catch (e) { setErr(String(e)); }
  };

  const removeProject = async (p: Project) => {
    if (!confirm(`Delete project “${p.name}” and all its scans, findings and uploaded `
      + `code? This cannot be undone.`)) return;
    try { await api.deleteProject(p.id); if (selected) openClient(selected); }
    catch (e) { setErr(String(e)); }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Clients & Projects</h1>
      <p className="text-muted text-sm mb-6">Organise code ownership: each client owns projects; each project holds code snapshots and scans.</p>
      {err && <div className="text-red-400 text-sm mb-4">{err}</div>}

      <div className="grid grid-cols-2 gap-6">
        <Card className="p-4">
          <div className="flex gap-2 mb-4">
            <Input placeholder="New client name" value={newClient}
              onChange={(e) => setNewClient(e.target.value)} />
            <Button onClick={addClient}>Add</Button>
          </div>
          <div className="space-y-1">
            {clients.map((c) => (
              <div key={c.id}
                className={`group flex items-center gap-2 pr-2 rounded-md ${selected === c.id ? "bg-emerald-600/20" : "hover:bg-border"}`}>
                <button onClick={() => openClient(c.id)} className="flex-1 text-left px-3 py-2 text-sm min-w-0">
                  <div className="font-medium truncate">{c.name}</div>
                  <div className="text-xs text-muted truncate">{c.slug}</div>
                </button>
                <button onClick={() => removeClient(c)} title="Delete client"
                  className="opacity-0 group-hover:opacity-100 text-muted hover:text-rose-300 text-sm px-1 transition">✕</button>
              </div>
            ))}
            {clients.length === 0 && <div className="text-muted text-sm">No clients yet.</div>}
          </div>
        </Card>

        <Card className="p-4">
          {selected ? (
            <>
              <div className="flex gap-2 mb-4">
                <Input placeholder="New project name" value={newProject}
                  onChange={(e) => setNewProject(e.target.value)} />
                <Button onClick={addProject}>Add</Button>
              </div>
              <div className="space-y-1">
                {(projects[selected] || []).map((p) => (
                  <div key={p.id} className="group flex items-center gap-2 pr-2 rounded-md hover:bg-border">
                    <button onClick={() => nav(`/projects/${p.id}`)}
                      className="flex-1 text-left px-3 py-2 text-sm min-w-0">
                      <div className="font-medium truncate">{p.name}</div>
                      {p.repo_url && <div className="text-xs text-muted truncate">{p.repo_url}</div>}
                    </button>
                    <button onClick={() => removeProject(p)} title="Delete project"
                      className="opacity-0 group-hover:opacity-100 text-muted hover:text-rose-300 text-sm px-1 transition">✕</button>
                  </div>
                ))}
                {(projects[selected] || []).length === 0 && <div className="text-muted text-sm">No projects yet.</div>}
              </div>
            </>
          ) : (
            <div className="text-muted text-sm">Select a client to see its projects.</div>
          )}
        </Card>
      </div>
    </div>
  );
}
