import { useEffect, useState } from "react";

export const ROUTES = [
  "overview",
  "map",
  "sessions",
  "graph",
  "attack",
  "deception",
  "telemetry",
  "network",
  "ai",
  "system",
] as const;
export type Route = (typeof ROUTES)[number];

export interface Location {
  route: Route;
  params: URLSearchParams;
}

function read(): Location {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const route = (ROUTES as readonly string[]).includes(path) ? (path as Route) : "overview";
  return { route, params: new URLSearchParams(query) };
}

export function useLocation(): Location {
  const [loc, setLoc] = useState(read);
  useEffect(() => {
    const on = () => setLoc(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return loc;
}

/** Navigate, optionally with drill-down params: go("sessions", { id }) */
export function go(route: Route, params?: Record<string, string>) {
  const q = params ? `?${new URLSearchParams(params).toString()}` : "";
  window.location.hash = `/${route}${q}`;
}

export function href(route: Route, params?: Record<string, string>) {
  const q = params ? `?${new URLSearchParams(params).toString()}` : "";
  return `#/${route}${q}`;
}
