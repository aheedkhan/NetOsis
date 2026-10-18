# NetOsis UI — Libraries, Tools & Reference Links

A curated stack for building the elegant, light-themed NetOsis cybersecurity dashboard, including an interactive 3D attack globe and connected investigation workspaces.

## Project
- [NetOsis GitHub repository](https://github.com/aheedkhan/NetOsis)

## Core frontend and design
- [React](https://react.dev/) — component-based UI.
- [TypeScript](https://www.typescriptlang.org/) — typed frontend and telemetry models.
- [Vite](https://vite.dev/) — frontend development/build tool, if compatible with the existing repo.
- [Tailwind CSS](https://tailwindcss.com/) — styling and design tokens.
- [shadcn/ui](https://ui.shadcn.com/) — adaptable component patterns.
- [Geist font](https://vercel.com/font) — clean interface typography.
- [Lucide React](https://lucide.dev/guide/packages/lucide-react) — consistent icons.
- [Motion](https://motion.dev/) — restrained UI animations.

## 3D globe and geographic visualization
- [react-globe.gl](https://github.com/vasturiano/react-globe.gl) — recommended first choice for interactive attack arcs, points, rings and country selection.
- [Globe.gl](https://globe.gl/) — underlying globe visualization library and examples.
- [Three.js](https://threejs.org/) — underlying 3D rendering.
- [React Three Fiber](https://r3f.docs.pmnd.rs/) — optional fully custom React 3D scenes.
- [Drei](https://github.com/pmndrs/drei) — optional helpers for React Three Fiber.
- [deck.gl](https://deck.gl/) — optional high-volume geographic overlays.
- [MapLibre GL JS](https://maplibre.org/maplibre-gl-js/docs/) — optional 2D geographic map.

## Network graphs and analytics
- [React Flow](https://reactflow.dev/) — recommended for interactive network topology.
- [Cytoscape.js](https://js.cytoscape.org/) — optional advanced attack-relationship graphs; add only if needed.
- [Apache ECharts](https://echarts.apache.org/) — charts, timelines, heatmaps and MITRE analytics.
- [TanStack Table](https://tanstack.com/table/latest) — telemetry/event tables.
- [xterm.js](https://xtermjs.org/) — terminal-style captured-session viewer.

## Data and backend integration
- [TanStack Query](https://tanstack.com/query/latest) — server-state caching and fetching.
- [Zustand](https://zustand.docs.pmnd.rs/) — shared UI and investigation state, if necessary.
- [FastAPI](https://fastapi.tiangolo.com/) — optional API layer for existing Python services; inspect the repository first.
- [MDN WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) — bidirectional live updates.
- [MDN Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) — one-way event streaming alternative.
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) — approximate public IP geolocation; subject to account/license requirements.

## Testing and quality
- [Playwright](https://playwright.dev/) — browser interaction, screenshots and end-to-end tests.
- [Vitest](https://vitest.dev/) — unit/component test runner.
- [axe-core](https://github.com/dequelabs/axe-core) — accessibility checks.

## Design references
- [Linear](https://linear.app/) — restrained product UI inspiration.
- [Vercel](https://vercel.com/) — typography and visual hierarchy inspiration.
- [Apple Design](https://developer.apple.com/design/) — clarity and interface craftsmanship.

## Recommended minimal starting stack

**React + TypeScript + Vite + Tailwind + shadcn/ui + Geist + Lucide + Motion + react-globe.gl + React Flow + Apache ECharts + TanStack Query + TanStack Table + Playwright.** Add the other libraries only for specific needs; avoid redundant graph or globe engines.

## Data integrity rules

- Inspect NetOsis's actual backend and event schemas before connecting the UI.
- Never show invented attack counts, IPs, MITRE mappings or paths as live telemetry.
- Only geolocate public IPs where lookup data is available. IP location is approximate, not verified attacker location.
- Use real source and destination coordinates for arcs; otherwise show an unmapped/unknown state.
- Clearly label synthetic fixtures as **Demo data**.
- Keep date ranges and filters consistent across the globe, KPIs, graphs and event feeds.

## Short Claude Code instruction

> Inspect the NetOsis repository and read the installed Taste skill (if available). Use the supplied dashboard screenshot as the visual reference. Implement a minimal, premium light-themed interface using the recommended stack above. Build a real-data-backed 3D attack globe with country/IP drilldowns, connected session investigations, network topology, MITRE analytics, telemetry and deception workspaces. Preserve the existing backend; implement and test all sidebar tabs. Do not misrepresent demo data as live data.
