import { useCallback, useEffect, useState } from "react";
import type { DashboardData } from "./types";

const REFRESH_MS = 12_000;

async function fetchDashboard(): Promise<DashboardData> {
  const res = await fetch("/v1/dashboard");
  if (!res.ok) throw new Error(`dashboard ${res.status}`);
  const data = await res.json();
  return {
    report: data.report,
    timeline: data.timeline ?? [],
    analytics: data.analytics,
    deception: data.deception,
  };
}

export function useDashboard(enabled = true) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    if (!enabled) return;
    try {
      const next = await fetchDashboard();
      setData(next);
      setError(null);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    refresh();
    const id = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh, enabled]);

  return { data, loading, error, lastRefresh, refresh };
}
