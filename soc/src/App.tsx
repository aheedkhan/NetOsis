import { lazy, Suspense, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WindowContext, type WindowKey } from "./lib/api";
import { useLocation } from "./lib/router";
import { Shell } from "./components/Shell";
import { Skeleton } from "./components/ui";

const Overview = lazy(() => import("./pages/Overview"));
const GlobalMap = lazy(() => import("./pages/GlobalMap"));
const Sessions = lazy(() => import("./pages/Sessions"));
const AttackGraph = lazy(() => import("./pages/AttackGraph"));
const Mitre = lazy(() => import("./pages/Mitre"));
const DeceptionPage = lazy(() => import("./pages/Deception"));
const Telemetry = lazy(() => import("./pages/Telemetry"));
const NetworkPage = lazy(() => import("./pages/Network"));
const AiPage = lazy(() => import("./pages/Ai"));
const SystemPage = lazy(() => import("./pages/System"));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 2, refetchOnWindowFocus: false, staleTime: 2000 } },
});

function readWindow(): WindowKey {
  try {
    const v = localStorage.getItem("netosis.window");
    if (v === "1h" || v === "24h" || v === "7d" || v === "all") return v;
  } catch {
    /* storage blocked: fall back to the default */
  }
  return "24h";
}

export default function App() {
  const [win, setWinState] = useState<WindowKey>(readWindow);
  const setWin = (w: WindowKey) => {
    setWinState(w);
    try {
      localStorage.setItem("netosis.window", w);
    } catch {
      /* not persisted */
    }
  };
  return (
    <QueryClientProvider client={queryClient}>
      <WindowContext.Provider value={{ win, setWin }}>
        <Routes />
      </WindowContext.Provider>
    </QueryClientProvider>
  );
}

function Routes() {
  const { route, params } = useLocation();
  const reduce = useReducedMotion();
  const page = {
    overview: <Overview />,
    map: <GlobalMap />,
    sessions: <Sessions params={params} />,
    graph: <AttackGraph params={params} />,
    attack: <Mitre params={params} />,
    deception: <DeceptionPage />,
    telemetry: <Telemetry params={params} />,
    network: <NetworkPage />,
    ai: <AiPage />,
    system: <SystemPage />,
  }[route];

  return (
    <Shell route={route}>
      <AnimatePresence mode="wait">
        <motion.div
          key={route}
          initial={reduce ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={reduce ? undefined : { opacity: 0, y: -4 }}
          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
        >
          <Suspense fallback={<PageSkeleton />}>{page}</Suspense>
        </motion.div>
      </AnimatePresence>
    </Shell>
  );
}

function PageSkeleton() {
  return (
    <div className="grid gap-4">
      <Skeleton className="h-7 w-56" />
      <div className="grid grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-[460px]" />
    </div>
  );
}
