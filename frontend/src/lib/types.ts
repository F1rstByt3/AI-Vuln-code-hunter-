export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingState = "proposed" | "confirmed" | "dismissed" | "needs_info";
export type ScanStatus =
  | "queued" | "running" | "needs_review" | "completed" | "failed" | "canceled";

export interface Client { id: string; name: string; slug: string; contact_email?: string; }
export interface Project {
  id: string; client_id: string; name: string; description?: string;
  repo_url?: string; default_branch: string;
}
export interface Artifact {
  id: string; project_id: string; kind: "upload" | "git" | "local"; status: string;
  label?: string; source_ref?: string; size_bytes: number; file_count: number;
  analyzable_count: number; error?: string;
}
export interface Scan {
  id: string; project_id: string; artifact_id: string; status: ScanStatus;
  config: Record<string, any>; summary: Record<string, any>; error?: string;
  started_at?: string; finished_at?: string; created_at: string;
}
export interface Finding {
  id: string; scan_id: string; title: string; description: string; severity: Severity;
  confidence: number; source: string; state: FindingState; cwe?: string; owasp?: string;
  category?: string; file_path?: string; line_start?: number; line_end?: number;
  code_snippet?: string; remediation?: string; human_question?: string; triage_note?: string;
  triaged_by?: string;
  raw?: {
    reviewed_by?: string; merged_count?: number;
    where_to_look?: string; attack_scenario?: string; proof_of_concept?: string;
    risk?: string; recommendation?: string; exploited_by?: string;
  } & Record<string, any>;
}
export interface McpServer {
  id: string; project_id?: string; name: string; kind: string; transport: string;
  url?: string; enabled: boolean;
}
export interface ArtifactFile {
  id: string; path: string; size_bytes: number; language: string | null;
  is_binary: boolean; is_vendored: boolean; included: boolean;
}
export interface ChatMessage { id: string; scan_id: string; role: string; content: string; }
export interface ModelRole {
  deployment: string; transport: string; reasoning_effort?: string | null;
}
export interface ModelRoles {
  chat?: ModelRole | null; reviewers: ModelRole[]; judge?: ModelRole | null;
  exploit?: ModelRole | null;
}
export interface FoundrySettings {
  endpoint?: string; deployment: string; api_version: string; api_style: string;
  use_agent_service: boolean;
  api_key_set: boolean; mock_mode: boolean; auth_mode: string;
  roles: ModelRoles;
}
export interface ScannerSettings {
  semgrep_enabled: boolean; semgrep_ruleset: string;
  sonarqube_enabled: boolean; sonarqube_url?: string | null;
  sonarqube_token_set: boolean;
}
export interface Endpoint {
  method: string; path: string; file_path: string; line: number;
  framework: string; handler: string; auth_hints: string[];
}
export interface Dashboard {
  project_id: string; total_findings: number; open_findings: number; needs_review: number;
  risk_score: number; by_severity: Record<Severity, number>;
  by_category: Record<string, number>; top_files: { path: string; count: number }[];
  latest_scan?: Scan; endpoints?: Endpoint[];
}
export interface ScanEvent {
  type: string; ts?: string; status?: string; message?: string; text?: string;
  finding?: Finding; role?: string; content?: string; summary?: Record<string, any>;
  error?: string;
}
