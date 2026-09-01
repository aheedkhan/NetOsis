import { useEffect, useState } from "react";
import type { TopologyMap } from "./types";

const REFRESH_MS = 8_000;

export function useTopology(enabled: boolean) {
  const [data, setData] = useState<TopologyMap | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch("/v1/topology");
        if (!res.ok) return;
        const next = await res.json();
        if (!cancelled) setData(next);
      } catch {
        // keep the last good map on a transient failure
      }
    };
    load();
    const id = window.setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [enabled]);

  return data;
}
