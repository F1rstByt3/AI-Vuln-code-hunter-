import React from "react";
import type { Severity } from "../lib/types";

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`rounded-xl border border-border bg-panel shadow-card ${className}`}>{children}</div>;
}

export function PageHeader({ title, subtitle, actions }: {
  title: React.ReactNode; subtitle?: React.ReactNode; actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-muted mt-1">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: {
  tabs: { key: string; label: React.ReactNode; badge?: React.ReactNode }[];
  active: string; onChange: (k: string) => void;
}) {
  return (
    <div className="flex gap-1 border-b border-border mb-6 overflow-x-auto">
      {tabs.map((t) => (
        <button key={t.key} onClick={() => onChange(t.key)}
          className={`px-4 py-2.5 text-sm -mb-px border-b-2 whitespace-nowrap transition ${
            active === t.key
              ? "border-accent text-slate-100 font-semibold"
              : "border-transparent text-muted hover:text-slate-300"}`}>
          {t.label}
          {t.badge != null && (
            <span className="ml-1.5 text-[11px] px-1.5 py-0.5 rounded-full bg-border/70 tabular-nums">
              {t.badge}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Button({
  children, onClick, variant = "primary", type = "button", disabled,
}: {
  children: React.ReactNode; onClick?: () => void;
  variant?: "primary" | "accent" | "ghost" | "danger"; type?: "button" | "submit"; disabled?: boolean;
}) {
  const styles = {
    primary: "bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm",
    accent: "bg-accent hover:bg-accent-hover text-white shadow-sm",
    ghost: "bg-transparent hover:bg-border text-slate-200 border border-border",
    danger: "bg-red-600/80 hover:bg-red-600 text-white",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition disabled:opacity-40 ${styles}`}>
      {children}
    </button>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props}
    className={`w-full px-3 py-2 rounded-md bg-bg border border-border text-sm outline-none focus:border-emerald-600 ${props.className || ""}`} />;
}

const SEV_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${SEV_COLORS[severity]}`}>
    {severity.toUpperCase()}</span>;
}

export function StateBadge({ state }: { state: string }) {
  const map: Record<string, string> = {
    proposed: "text-slate-300", confirmed: "text-emerald-300",
    dismissed: "text-slate-500 line-through", needs_info: "text-fuchsia-300",
  };
  return <span className={`text-xs font-medium ${map[state] || ""}`}>{state.replace("_", " ")}</span>;
}

export function Spinner() {
  return <span className="inline-block w-3 h-3 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />;
}
