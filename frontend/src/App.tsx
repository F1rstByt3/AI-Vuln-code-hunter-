import { NavLink, Route, Routes } from "react-router-dom";
import ClientsPage from "./pages/ClientsPage";
import ProjectPage from "./pages/ProjectPage";
import ScanPage from "./pages/ScanPage";
import SettingsPage from "./pages/SettingsPage";

function Nav() {
  const cls = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition ${
      isActive
        ? "bg-accent/15 text-accent-hover ring-1 ring-accent/30"
        : "text-slate-300 hover:bg-border/60"
    }`;
  return (
    <aside className="w-60 shrink-0 border-r border-border bg-panel/80 backdrop-blur p-4 flex flex-col">
      <div className="mb-8 flex items-center gap-2.5">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-accent to-emerald-500 grid place-items-center text-lg shadow-glow">
          🛡️
        </div>
        <div>
          <div className="text-[15px] font-bold tracking-tight leading-tight">Vuln Hunter</div>
          <div className="text-[11px] text-muted">AI security review</div>
        </div>
      </div>
      <nav className="space-y-1">
        <NavLink to="/" className={cls} end>
          <span>📁</span> Clients &amp; Projects
        </NavLink>
        <NavLink to="/settings" className={cls}>
          <span>⚙️</span> Settings
        </NavLink>
      </nav>
      <div className="mt-auto text-[11px] text-muted pt-4 border-t border-border leading-relaxed">
        <div className="font-medium text-slate-400 mb-0.5">SAST · DAST · AI</div>
        static analysis, AI review, and live confirmation
      </div>
    </aside>
  );
}

export default function App() {
  return (
    <div className="flex h-full">
      <Nav />
      <main className="flex-1 overflow-auto">
        <div className="max-w-6xl mx-auto px-6 py-7">
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
