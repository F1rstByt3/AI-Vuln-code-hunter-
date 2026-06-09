import React from "react";
import type { Severity } from "../lib/types";

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`rounded-lg border border-border bg-panel ${className}`}>{children}</div>;
}

export function Button({
  children, onClick, variant = "primary", type = "button", disabled,
}: {
  children: React.ReactNode; onClick?: () => void;
  variant?: "primary" | "ghost" | "danger"; type?: "button" | "submit"; disabled?: boolean;
}) {
  const styles = {
    primary: "bg-emerald-600 hover:bg-emerald-500 text-white",
    ghost: "bg-transparent hover:bg-border text-slate-200 border border-border",
    danger: "bg-red-600/80 hover:bg-red-600 text-white",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`px-3 py-1.5 rounded-md text-sm font-medium transition disabled:opacity-40 ${styles}`}>
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
