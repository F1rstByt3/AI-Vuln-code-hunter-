import { useEffect, useMemo, useState } from "react";
import type { ArtifactFile } from "../lib/types";

interface TreeNode {
  name: string;
  path: string;
  children: Map<string, TreeNode>;
  file?: ArtifactFile;
}

function buildTree(files: ArtifactFile[]): TreeNode {
  const root: TreeNode = { name: "", path: "", children: new Map() };
  for (const f of files) {
    const parts = f.path.split("/");
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      if (!node.children.has(seg)) {
        node.children.set(seg, {
          name: seg,
          path: parts.slice(0, i + 1).join("/"),
          children: new Map(),
        });
      }
      node = node.children.get(seg)!;
    }
    node.file = f;
  }
  return root;
}

function allPaths(node: TreeNode): string[] {
  if (node.file) return [node.path];
  const out: string[] = [];
  for (const child of node.children.values()) out.push(...allPaths(child));
  return out;
}

type CheckState = "checked" | "unchecked" | "partial";

function getCheckState(node: TreeNode, selected: Set<string>): CheckState {
  if (node.file) return selected.has(node.path) ? "checked" : "unchecked";
  const paths = allPaths(node);
  if (paths.length === 0) return "unchecked";
  const count = paths.filter((p) => selected.has(p)).length;
  if (count === 0) return "unchecked";
  if (count === paths.length) return "checked";
  return "partial";
}

function Checkbox({ state, onChange }: { state: CheckState; onChange: () => void }) {
  return (
    <span onClick={(e) => { e.stopPropagation(); onChange(); }}
      className="inline-flex items-center justify-center w-4 h-4 rounded border border-border cursor-pointer
        hover:border-emerald-500 text-[10px] leading-none select-none flex-shrink-0"
      style={{ background: state === "checked" ? "#059669" : state === "partial" ? "#065f46" : "transparent" }}>
      {state === "checked" ? "✓" : state === "partial" ? "–" : ""}
    </span>
  );
}

const LANG_ICONS: Record<string, string> = {
  python: "🐍", javascript: "JS", typescript: "TS", java: "☕", go: "Go",
  rust: "🦀", ruby: "💎", csharp: "C#", cpp: "C+", c: "C", html: "H", css: "🎨",
  json: "{}", yaml: "Y", xml: "X", sql: "DB", shell: "sh", markdown: "md",
};

function FileTreeNode({ node, depth, selected, onToggle, expanded, setExpanded }: {
  node: TreeNode; depth: number; selected: Set<string>;
  onToggle: (paths: string[], add: boolean) => void;
  expanded: Set<string>; setExpanded: (fn: (s: Set<string>) => Set<string>) => void;
}) {
  const isDir = !node.file;
  const isOpen = expanded.has(node.path);
  const checkState = getCheckState(node, selected);
  const paths = useMemo(() => allPaths(node), [node]);

  const toggle = () => {
    onToggle(paths, checkState !== "checked");
  };

  const toggleExpand = () => {
    setExpanded((s) => {
      const next = new Set(s);
      if (next.has(node.path)) next.delete(node.path);
      else next.add(node.path);
      return next;
    });
  };

  const sortedChildren = useMemo(() => {
    const dirs: TreeNode[] = [];
    const files: TreeNode[] = [];
    for (const c of node.children.values()) {
      if (c.file) files.push(c); else dirs.push(c);
    }
    dirs.sort((a, b) => a.name.localeCompare(b.name));
    files.sort((a, b) => a.name.localeCompare(b.name));
    return [...dirs, ...files];
  }, [node]);

  const langIcon = node.file?.language ? LANG_ICONS[node.file.language] : null;
  const dimmed = node.file && (!node.file.included || node.file.is_binary || node.file.is_vendored);

  return (
    <div>
      <div
        className={`flex items-center gap-1.5 py-0.5 px-1 rounded cursor-pointer hover:bg-border/50 text-sm ${dimmed ? "opacity-50" : ""}`}
        style={{ paddingLeft: `${depth * 16 + 4}px` }}
        onClick={isDir ? toggleExpand : undefined}
      >
        <Checkbox state={checkState} onChange={toggle} />
        {isDir && (
          <span className="text-[11px] text-muted w-3 text-center flex-shrink-0">
            {isOpen ? "▼" : "▶"}
          </span>
        )}
        <span className={`flex-shrink-0 text-[11px] w-5 text-center ${isDir ? "text-amber-300" : "text-muted"}`}>
          {isDir ? "📁" : (langIcon || "📄")}
        </span>
        <span className="truncate flex-1">{node.name}</span>
        {node.file && (
          <span className="text-[10px] text-muted flex-shrink-0">
            {node.file.language || ""} {formatSize(node.file.size_bytes)}
          </span>
        )}
        {isDir && (
          <span className="text-[10px] text-muted flex-shrink-0">
            {paths.length} files
          </span>
        )}
      </div>
      {isDir && isOpen && sortedChildren.map((c) => (
        <FileTreeNode key={c.path} node={c} depth={depth + 1} selected={selected}
          onToggle={onToggle} expanded={expanded} setExpanded={setExpanded} />
      ))}
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}K`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
}

export default function FileTree({ files, selectedPaths, onSelectionChange }: {
  files: ArtifactFile[];
  selectedPaths: string[];
  onSelectionChange: (paths: string[]) => void;
}) {
  const tree = useMemo(() => buildTree(files), [files]);
  const selected = useMemo(() => new Set(selectedPaths), [selectedPaths]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const allFilePaths = useMemo(() => files.map((f) => f.path), [files]);

  useEffect(() => {
    if (tree.children.size > 0 && expanded.size === 0) {
      const initial = new Set<string>();
      for (const c of tree.children.values()) {
        if (!c.file) initial.add(c.path);
      }
      setExpanded(initial);
    }
  }, [tree]);

  const onToggle = (paths: string[], add: boolean) => {
    const next = new Set(selected);
    for (const p of paths) {
      if (add) next.add(p); else next.delete(p);
    }
    onSelectionChange(Array.from(next));
  };

  const allSelected = selected.size === allFilePaths.length && allFilePaths.length > 0;
  const someSelected = selected.size > 0 && !allSelected;

  return (
    <div>
      <div className="flex items-center justify-between mb-1 text-xs text-muted px-1">
        <div className="flex items-center gap-2">
          <Checkbox
            state={allSelected ? "checked" : someSelected ? "partial" : "unchecked"}
            onChange={() => onSelectionChange(allSelected ? [] : allFilePaths)}
          />
          <span>
            {selected.size === 0
              ? "All files (no filter)"
              : `${selected.size} / ${allFilePaths.length} files selected`}
          </span>
        </div>
        <div className="flex gap-2">
          <button onClick={() => {
            const all = new Set<string>();
            const collectDirs = (n: TreeNode) => {
              if (!n.file && n.path) all.add(n.path);
              for (const c of n.children.values()) collectDirs(c);
            };
            collectDirs(tree);
            setExpanded(all);
          }} className="hover:text-slate-200">Expand all</button>
          <button onClick={() => setExpanded(new Set())} className="hover:text-slate-200">Collapse</button>
        </div>
      </div>
      <div className="max-h-64 overflow-auto border border-border rounded-md p-1 bg-bg">
        {tree.children.size === 0 && (
          <div className="text-muted text-sm p-2">No files indexed yet. Run a scan first.</div>
        )}
        {Array.from(tree.children.values())
          .sort((a, b) => {
            const ad = !a.file ? 0 : 1;
            const bd = !b.file ? 0 : 1;
            return ad - bd || a.name.localeCompare(b.name);
          })
          .map((c) => (
            <FileTreeNode key={c.path} node={c} depth={0} selected={selected}
              onToggle={onToggle} expanded={expanded} setExpanded={setExpanded} />
          ))
        }
      </div>
    </div>
  );
}
