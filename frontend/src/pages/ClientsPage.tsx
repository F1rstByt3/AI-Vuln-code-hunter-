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
              <button key={c.id} onClick={() => openClient(c.id)}
                className={`w-full text-left px-3 py-2 rounded-md text-sm ${selected === c.id ? "bg-emerald-600/20" : "hover:bg-border"}`}>
                <div className="font-medium">{c.name}</div>
                <div className="text-xs text-muted">{c.slug}</div>
              </button>
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
                  <button key={p.id} onClick={() => nav(`/projects/${p.id}`)}
                    className="w-full text-left px-3 py-2 rounded-md text-sm hover:bg-border">
                    <div className="font-medium">{p.name}</div>
                    {p.repo_url && <div className="text-xs text-muted">{p.repo_url}</div>}
                  </button>
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
