import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api } from "../lib/api";
import type { Client, Project } from "../lib/types";

const LS_KEY = "sidebar:expanded";

function loadExpanded(): Set<string> {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch { return new Set(); }
}
function saveExpanded(s: Set<string>) {
  try { localStorage.setItem(LS_KEY, JSON.stringify([...s])); } catch { /* ignore */ }
}

/** Collapsible Clients → Projects tree for the sidebar. Clients expand to lazy-
 *  load their projects; the open client and active project are highlighted, and
 *  the client owning the currently-viewed project auto-expands. */
export function SidebarTree() {
  const [clients, setClients] = useState<Client[] | null>(null);
  const [projects, setProjects] = useState<Record<string, Project[]>>({});
  const [expanded, setExpanded] = useState<Set<string>>(loadExpanded);
  const [err, setErr] = useState(false);
  const loc = useLocation();
  // SidebarTree renders outside <Routes>, so useParams() is empty here — read
  // the active project id straight from the path.
  const projectId = loc.pathname.match(/^\/projects\/([^/]+)/)?.[1];

  // Refresh the client list whenever we land back on a top-level route (so new
  // clients/projects created on the Clients page show up without a reload).
  useEffect(() => {
    api.listClients().then((c) => { setClients(c); setErr(false); })
      .catch(() => setErr(true));
  }, [loc.pathname === "/" ? "home" : ""]);

  const loadProjects = (clientId: string) =>
    api.listProjects(clientId)
      .then((p) => setProjects((m) => ({ ...m, [clientId]: p })))
      .catch(() => setProjects((m) => ({ ...m, [clientId]: [] })));

  const toggle = (clientId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(clientId)) next.delete(clientId);
      else { next.add(clientId); if (!projects[clientId]) loadProjects(clientId); }
      saveExpanded(next);
      return next;
    });
  };

  // Auto-expand the client that owns the project currently being viewed.
  useEffect(() => {
    if (!projectId) return;
    api.getProject(projectId).then((p) => {
      setExpanded((prev) => {
        if (prev.has(p.client_id)) return prev;
        const next = new Set(prev).add(p.client_id);
        saveExpanded(next);
        return next;
      });
      if (!projects[p.client_id]) loadProjects(p.client_id);
    }).catch(() => { /* ignore */ });
  }, [projectId]);

  // Keep expanded clients' project lists fresh across navigations.
  useEffect(() => {
    for (const id of expanded) if (!projects[id]) loadProjects(id);
  }, [[...expanded].join()]);

  if (err) return <div className="text-[11px] text-muted px-3 py-2">Couldn't load clients.</div>;
  if (!clients) return <div className="text-[11px] text-muted px-3 py-2">Loading…</div>;
  if (clients.length === 0)
    return <div className="text-[11px] text-muted px-3 py-2">No clients yet.</div>;

  return (
    <div className="space-y-0.5">
      {clients.map((c) => {
        const open = expanded.has(c.id);
        const projs = projects[c.id];
        return (
          <div key={c.id}>
            <button onClick={() => toggle(c.id)}
              className="w-full flex items-center gap-1.5 px-2 py-1.5 rounded-md text-sm text-slate-300 hover:bg-border/60 transition text-left">
              <span className="w-3 text-[10px] text-muted">{open ? "▾" : "▸"}</span>
              <span className="truncate flex-1">{c.name}</span>
              {projs && <span className="text-[10px] text-muted tabular-nums">{projs.length}</span>}
            </button>
            {open && (
              <div className="ml-4 border-l border-border pl-2 py-0.5 space-y-0.5">
                {projs === undefined && <div className="text-[11px] text-muted px-2 py-1">Loading…</div>}
                {projs && projs.length === 0 && (
                  <div className="text-[11px] text-muted px-2 py-1">No projects</div>
                )}
                {projs?.map((p) => (
                  <NavLink key={p.id} to={`/projects/${p.id}`}
                    className={({ isActive }) =>
                      `block px-2 py-1 rounded-md text-[13px] truncate transition ${
                        isActive
                          ? "bg-accent/15 text-accent-hover ring-1 ring-accent/30"
                          : "text-slate-400 hover:bg-border/60 hover:text-slate-200"}`}
                    title={p.name}>
                    {p.name}
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
