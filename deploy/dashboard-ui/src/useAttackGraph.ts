import { useCallback, useEffect, useState } from "react";
import type { ActorAttackGraph, GraphNode } from "./types";

export function useAttackGraph(enabled: boolean, refreshKey?: string) {
  const [machines, setMachines] = useState<GraphNode[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [actorGraph, setActorGraph] = useState<ActorAttackGraph | null>(null);
  const [loadingActor, setLoadingActor] = useState(false);
  const [loadingList, setLoadingList] = useState(false);

  const loadMachines = useCallback(async () => {
    if (!enabled) return;
    setLoadingList(true);
    try {
      const res = await fetch("/v1/graph");
      if (!res.ok) throw new Error(`graph ${res.status}`);
      const data = await res.json();
      const list: GraphNode[] = data.machines ?? (data.nodes ?? []).filter((n: GraphNode) => n.type === "machine");
      setMachines(list.sort((a, b) => (b.events ?? 0) - (a.events ?? 0)));
    } catch {
      setMachines([]);
    } finally {
      setLoadingList(false);
    }
  }, [enabled]);

  useEffect(() => {
    loadMachines();
  }, [loadMachines, refreshKey]);

  useEffect(() => {
    if (!enabled || !selected) {
      setActorGraph(null);
      return;
    }
    let cancelled = false;
    setLoadingActor(true);
    fetch(`/v1/graph/actor?key=${encodeURIComponent(selected)}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data) => {
        if (!cancelled) setActorGraph(data);
      })
      .catch(() => {
        if (!cancelled) setActorGraph(null);
      })
      .finally(() => {
        if (!cancelled) setLoadingActor(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected, enabled]);

  return {
    machines,
    selected,
    setSelected,
    actorGraph,
    loadingActor,
    loadingList,
    reload: loadMachines,
  };
}
