import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { ScanEvent, StageInfo, TokenUsage } from "../lib/types";

/** Subscribes to a scan's SSE stream: live narration tokens, status, stage
 *  progress, token usage, findings, chat. */
export function useScanEvents(scanId: string | undefined) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<string>("");
  const [narration, setNarration] = useState<string>("");
  const [live, setLive] = useState(false);
  const [stages, setStages] = useState<Record<string, StageInfo>>({});
  const [tokens, setTokens] = useState<TokenUsage | undefined>();
  const [paused, setPaused] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setEvents([]); setNarration(""); setStatus("");
    setStages({}); setTokens(undefined); setPaused(false);
    const es = new EventSource(api.eventsUrl(scanId));
    esRef.current = es;
    setLive(true);
    es.onmessage = (m) => {
      const ev: ScanEvent = JSON.parse(m.data);
      if (ev.type === "heartbeat") return;
      if (ev.type === "token" && ev.text) setNarration((s) => s + ev.text);
      if (ev.type === "status" && ev.status) setStatus(ev.status);
      if (ev.type === "stages" && ev.stages) {
        setStages(Object.fromEntries(ev.stages.map((s) => [s.stage, s])));
      }
      if (ev.type === "stage" && ev.stage) {
        setStages((prev) => ({ ...prev, [ev.stage!]: { ...prev[ev.stage!], ...(ev as any) } as StageInfo }));
      }
      if (ev.type === "tokens" && ev.tokens) setTokens(ev.tokens);
      if (ev.type === "control") {
        if (ev.control === "paused") setPaused(true);
        if (ev.control === "resumed" || ev.control === "resume") setPaused(false);
      }
      if (ev.type === "done" && ev.summary?.tokens) setTokens(ev.summary.tokens);
      setEvents((prev) => [...prev, ev]);
      if (["done", "failed", "canceled"].includes(ev.type)) {
        setStatus(ev.type === "done" ? (ev.status || "completed") : ev.type);
        setPaused(false);
        es.close(); setLive(false);
      }
    };
    es.onerror = () => { es.close(); setLive(false); };
    return () => { es.close(); esRef.current = null; };
  }, [scanId]);

  return { events, status, narration, live, stages, tokens, paused };
}
