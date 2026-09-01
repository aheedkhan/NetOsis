import { useEffect, useState } from "react";
import type { SystemMetrics } from "./types";

// Host resource usage changes fast enough (CPU% especially) that the main
// dashboard's 12s refresh would make this panel look frozen — poll it on
// its own short cycle instead.
const REFRESH_MS = 2_000;

export function useSystemMetrics(enabled = true) {
  const [data, setData] = useState<SystemMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;

    async function poll() {
      try {
        const res = await fetch("/v1/system");
        if (!res.ok) throw new Error(`system ${res.status}`);
        const next = (await res.json()) as SystemMetrics;
        if (!cancelled) {
          setData(next.available === false ? null : next);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load");
      }
    }

    poll();
    const id = window.setInterval(poll, REFRESH_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [enabled]);

  return { data, error };
}
