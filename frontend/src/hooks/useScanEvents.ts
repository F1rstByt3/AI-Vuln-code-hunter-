import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { ScanEvent } from "../lib/types";

/** Subscribes to a scan's SSE stream: live narration tokens, status, findings, chat. */
export function useScanEvents(scanId: string | undefined) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<string>("");
  const [narration, setNarration] = useState<string>("");
  const [live, setLive] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setEvents([]); setNarration(""); setStatus("");
    const es = new EventSource(api.eventsUrl(scanId));
    esRef.current = es;
    setLive(true);
    es.onmessage = (m) => {
      const ev: ScanEvent = JSON.parse(m.data);
      if (ev.type === "heartbeat") return;
      if (ev.type === "token" && ev.text) setNarration((s) => s + ev.text);
      if (ev.type === "status" && ev.status) setStatus(ev.status);
      setEvents((prev) => [...prev, ev]);
      if (["done", "failed", "canceled"].includes(ev.type)) {
        setStatus(ev.type === "done" ? (ev.status || "completed") : ev.type);
        es.close(); setLive(false);
      }
    };
    es.onerror = () => { es.close(); setLive(false); };
    return () => { es.close(); esRef.current = null; };
  }, [scanId]);

  return { events, status, narration, live };
}
