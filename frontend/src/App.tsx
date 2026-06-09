import { NavLink, Route, Routes } from "react-router-dom";
import ClientsPage from "./pages/ClientsPage";
import ProjectPage from "./pages/ProjectPage";
import ScanPage from "./pages/ScanPage";
import SettingsPage from "./pages/SettingsPage";

function Nav() {
  const cls = ({ isActive }: { isActive: boolean }) =>
    `block px-3 py-2 rounded-md text-sm ${isActive ? "bg-emerald-600/20 text-emerald-300" : "text-slate-300 hover:bg-border"}`;
  return (
    <aside className="w-56 shrink-0 border-r border-border bg-panel p-4 flex flex-col">
      <div className="mb-6">
        <div className="text-lg font-bold tracking-tight">🛡️ Vuln Hunter</div>
        <div className="text-xs text-muted">AI code-security review</div>
      </div>
      <nav className="space-y-1">
        <NavLink to="/" className={cls} end>Clients & Projects</NavLink>
        <NavLink to="/settings" className={cls}>Settings · Foundry · MCP</NavLink>
      </nav>
      <div className="mt-auto text-[11px] text-muted pt-4 border-t border-border">
        SAST-first · LLM-second · human-in-the-loop
      </div>
    </aside>
  );
}

export default function App() {
  return (
    <div className="flex h-full">
      <Nav />
      <main className="flex-1 overflow-auto">
        <div className="max-w-6xl mx-auto p-6">
          <Routes>
            <Route path="/" element={<ClientsPage />} />
            <Route path="/projects/:projectId" element={<ProjectPage />} />
            <Route path="/scans/:scanId" element={<ScanPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
