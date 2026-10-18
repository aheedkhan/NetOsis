import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import GlobeGL, { type GlobeMethods } from "react-globe.gl";
import { useReducedMotion } from "motion/react";
import {
  Minus,
  Pause,
  Play,
  Plus,
  LocateFixed,
  Globe as GlobeIcon,
  Shield,
  Landmark,
  Compass,
  Navigation,
  Crosshair,
  Anchor,
} from "lucide-react";
import * as THREE from "three";
import type { GeoData, GeoPoint } from "../lib/api";
import { LEVEL } from "../lib/format";
import { href } from "../lib/router";

export const REGIONS: {
  id: string;
  label: string;
  lat: number;
  lng: number;
  /** zoom relative to the fitted world view (1 = whole globe, smaller = closer) */
  alt: number;
  icon: typeof GlobeIcon;
  box?: [number, number, number, number];
}[] = [
  { id: "world", label: "World", lat: 22, lng: 25, alt: 1, icon: GlobeIcon },
  { id: "na", label: "North America", lat: 42, lng: -98, alt: 0.78, icon: Shield, box: [7, 84, -170, -50] },
  { id: "eu", label: "Europe", lat: 50, lng: 12, alt: 0.72, icon: Landmark, box: [34, 72, -25, 45] },
  { id: "as", label: "Asia", lat: 30, lng: 90, alt: 0.82, icon: Compass, box: [-11, 78, 45, 180] },
  { id: "sa", label: "South America", lat: -18, lng: -60, alt: 0.78, icon: Navigation, box: [-57, 13, -92, -30] },
  { id: "af", label: "Africa", lat: 3, lng: 20, alt: 0.78, icon: Crosshair, box: [-36, 38, -20, 52] },
  { id: "oc", label: "Oceania", lat: -25, lng: 140, alt: 0.78, icon: Anchor, box: [-50, 0, 110, 180] },
];

/**
 * Camera altitude that makes the globe's radius a fixed share of the card, so it
 * fits any size with room left for the arcs above it. globe.gl uses a 50° vertical
 * FOV; altitude is in globe radii above the surface.
 */
function fitAltitude(width: number, height: number, compact: boolean) {
  const share = compact ? 0.4 : 0.36; // globe radius as a share of the shorter side
  const rPx = share * Math.min(width, height);
  const tanTheta = (rPx * Math.tan((25 * Math.PI) / 180)) / (height / 2);
  const theta = Math.atan(tanTheta);
  return Math.min(6, Math.max(1.2, 1 / Math.sin(theta) - 1));
}

export function inRegion(p: { lat: number; lng: number }, regionId: string) {
  const r = REGIONS.find((x) => x.id === regionId);
  if (!r?.box) return true;
  const [s, n, w, e] = r.box;
  return p.lat >= s && p.lat <= n && p.lng >= w && p.lng <= e;
}

export function getCountryFlag(iso?: string): string {
  if (!iso || iso.length !== 2) return "🌐";
  const codePoints = iso
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

const SEV_COLOR = { high: "#ef4444", medium: "#f59e0b", low: "#38bdf8", site: "#2563eb" } as const;
type Sev = keyof typeof SEV_COLOR;
const sevOf = (lvl: GeoPoint["level"]): Sev => (lvl === "CRITICAL" || lvl === "HIGH" ? "high" : lvl === "MEDIUM" ? "medium" : "low");

type Marker = GeoPoint & { sources: GeoPoint[]; isSite?: boolean };

/** Soft glowing dot texture (one per colour), drawn once on a canvas. */
const glowCache = new Map<string, THREE.Texture>();
function glowTexture(color: string) {
  const hit = glowCache.get(color);
  if (hit) return hit;
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const ctx = c.getContext("2d")!;
  const g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.16, "rgba(255,255,255,0.95)");
  g.addColorStop(0.24, hexA(color, 1));
  g.addColorStop(0.45, hexA(color, 0.35));
  g.addColorStop(1, hexA(color, 0));
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, 128, 128);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  glowCache.set(color, t);
  return t;
}

/** Glass shell: fresnel rim + a fixed specular highlight, like light on a glass ball. */
function glassShell(radius: number) {
  const mat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    uniforms: {},
    vertexShader: `
      varying vec3 vN; varying vec3 vV;
      void main() {
        vec4 mv = modelViewMatrix * vec4(position, 1.0);
        vN = normalize(normalMatrix * normal);
        vV = normalize(-mv.xyz);
        gl_Position = projectionMatrix * mv;
      }`,
    fragmentShader: `
      varying vec3 vN; varying vec3 vV;
      void main() {
        float rim = pow(1.0 - max(dot(vN, vV), 0.0), 3.0);
        vec3 L = normalize(vec3(-0.55, 0.65, 0.55));
        vec3 H = normalize(L + vV);
        float spec = pow(max(dot(vN, H), 0.0), 140.0);
        float sheen = pow(max(dot(vN, L), 0.0), 8.0) * 0.06;
        vec3 col = mix(vec3(0.62, 0.84, 1.0), vec3(1.0), spec);
        gl_FragColor = vec4(col, clamp(rim * 0.6 + spec * 0.4 + sheen, 0.0, 0.8));
      }`,
  });
  const mesh = new THREE.Mesh(new THREE.SphereGeometry(radius, 96, 96), mat);
  mesh.name = "netosis-glass";
  mesh.renderOrder = 2;
  return mesh;
}

function makeGlobeMaterial() {
  const loader = new THREE.TextureLoader();
  // NASA Blue Marble (real satellite imagery) + relief + a water mask for glossy oceans.
  const map = loader.load("/img/earth-blue-marble.jpg");
  map.colorSpace = THREE.SRGBColorSpace;
  map.anisotropy = 8;
  return new THREE.MeshPhongMaterial({
    map,
    bumpMap: loader.load("/img/earth-topology.png"),
    bumpScale: 2.2,
    specularMap: loader.load("/img/earth-water.png"),
    specular: new THREE.Color("#8fc3ff"),
    shininess: 32,
  });
}

/** Thin, slowly drifting cloud layer (alpha from the cloud map). */
function cloudLayer(radius: number) {
  const alpha = new THREE.TextureLoader().load("/img/clouds-2k.jpg");
  const mesh = new THREE.Mesh(
    new THREE.SphereGeometry(radius, 96, 96),
    new THREE.MeshPhongMaterial({ color: 0xffffff, alphaMap: alpha, transparent: true, opacity: 0.6, depthWrite: false }),
  );
  mesh.name = "netosis-clouds";
  mesh.renderOrder = 1;
  return mesh;
}

function chipEl(p: Marker, onPick: (p: Marker) => void) {
  const color = SEV_COLOR[sevOf(p.level)];
  const el = document.createElement("div");
  el.style.pointerEvents = "none";
  el.innerHTML = `
    <div data-card data-pinned="0" title="Click for details" style="opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s;pointer-events:auto;cursor:pointer;
      transform:translate(10px,-50%);display:flex;align-items:center;gap:5px;width:max-content;padding:3px 8px 3px 6px;border-radius:999px;
      background:rgba(255,255,255,.82);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
      border:1px solid rgba(255,255,255,.95);box-shadow:0 0 0 1px rgba(20,36,58,.07),0 6px 16px -6px rgba(15,40,90,.35);
      font:600 11px/1.3 Geist,system-ui,sans-serif;color:#14243a">
      <span style="width:7px;height:7px;border-radius:999px;background:${color}"></span>
      <span>${getCountryFlag(p.iso)} ${esc(p.country || p.city || "Unknown")}</span>
      <span style="font-family:'Geist Mono',ui-monospace,monospace;font-weight:500;color:#64748b">${p.events}</span>
    </div>`;
  const card = el.querySelector<HTMLElement>("[data-card]")!;
  card.addEventListener("click", (e) => {
    e.stopPropagation();
    onPick(p);
  });
  card.addEventListener("pointerdown", (e) => e.stopPropagation());
  return el;
}

function calloutEl(p: Marker, pinned: boolean, side: "right" | "left", onPick: (p: Marker) => void) {
  const sev = sevOf(p.level);
  const label = p.level === "CRITICAL" ? "Critical" : p.level[0] + p.level.slice(1).toLowerCase();
  const pill =
    sev === "high"
      ? "background:#fdecee;color:#c8323f"
      : sev === "medium"
        ? "background:#fef5e4;color:#9a5b00"
        : "background:#e8f2fe;color:#1d4ed8";
  const el = document.createElement("div");
  el.style.pointerEvents = "none";
  el.innerHTML = `
    <div data-card data-pinned="${pinned ? 1 : 0}" style="opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s;pointer-events:auto;cursor:pointer;transform:${side === "left" ? "translate(calc(-100% - 14px),-50%)" : "translate(14px,-50%)"};width:max-content;max-width:260px;padding:9px 12px;border-radius:12px;
      background:rgba(255,255,255,.78);backdrop-filter:blur(12px) saturate(1.6);-webkit-backdrop-filter:blur(12px) saturate(1.6);
      border:1px solid rgba(255,255,255,.95);box-shadow:0 0 0 1px rgba(20,36,58,.07),0 10px 28px -8px rgba(15,40,90,.35);
      font:500 11px/1.45 Geist,system-ui,sans-serif;color:#4d5d73;${pinned ? "outline:2px solid rgba(37,99,235,.35);" : ""}">
      <div style="display:flex;align-items:center;gap:6px;font-weight:600;font-size:12px;color:#14243a">
        <span>${getCountryFlag(p.iso)}</span><span>${esc(p.country || p.city || "Unknown")}</span>
        ${p.demo ? '<span style="margin-left:2px;padding:0 5px;border-radius:999px;background:#fef5e4;color:#9a5b00;font-size:9.5px">Demo</span>' : ""}
      </div>
      <div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:10.5px">IP: ${esc(p.sources.length > 1 ? `${p.ip} +${p.sources.length - 1}` : p.ip)}</div>
      <div>Attacks: <b style="color:#14243a">${p.events}</b></div>
      <div>Severity: <span style="padding:1px 6px;border-radius:999px;font-weight:600;font-size:10px;${pill}">${label}</span></div>
      ${
        pinned
          ? `<div style="margin-top:4px">Profile: <b style="color:#14243a">${esc(p.persona || "—")}</b></div>
             <div>Hit: ${esc(p.hosts.join(", ") || "—")}</div>
             <div style="display:flex;gap:6px;margin-top:8px;pointer-events:auto">
               ${link(href("sessions", { ip: p.ip }), "Sessions")}
               ${link(href("graph", { ip: p.ip }), "Attack graph")}
               ${link(href("telemetry", { q: p.ip }), "Events")}
             </div>`
          : `<div style="margin-top:3px;color:#2563eb;font-size:10px;font-weight:600">Click for details →</div>`
      }
    </div>`;
  const card = el.querySelector<HTMLElement>("[data-card]")!;
  card.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).closest("a")) return; // drill links navigate on their own
    e.stopPropagation();
    onPick(p);
  });
  // don't let a click on the card start a globe drag
  card.addEventListener("pointerdown", (e) => e.stopPropagation());
  return el;
}

/**
 * Keep the same object for the same key across data refreshes. three-globe joins
 * layer data by object identity: new objects every poll would rebuild every arc and
 * restart its dash animation, so instead we update the existing objects in place.
 */
function useStable<T extends object>(items: T[], key: (t: T) => string): T[] {
  const cache = useRef(new Map<string, T>());
  const prev = useRef<T[]>([]);
  return useMemo(() => {
    const next = new Map<string, T>();
    let changed = items.length !== prev.current.length;
    const out = items.map((it, i) => {
      const k = key(it);
      const old = cache.current.get(k);
      const obj = old ? Object.assign(old, it) : it;
      next.set(k, obj);
      if (prev.current[i] !== obj) changed = true;
      return obj;
    });
    cache.current = next;
    if (changed) prev.current = out;
    return prev.current;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);
}

function link(to: string, text: string) {
  return `<a href="${to}" style="white-space:nowrap;padding:3px 8px;border-radius:8px;background:#eaf1fe;color:#1d4ed8;font-weight:600;font-size:10.5px;text-decoration:none">${text} →</a>`;
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function Globe({
  data,
  height,
  region = "world",
  selected,
  onSelect,
  compact = false,
  inset = 0,
  insetRight = 0,
}: {
  insetRight?: number;
  /** px reserved on the left for an overlay (e.g. the region list); the globe centres in the rest */
  inset?: number;
  data: GeoData | undefined;
  height: number;
  region?: string;
  selected?: string | null;
  onSelect?: (p: GeoPoint | null) => void;
  compact?: boolean;
}) {
  const reduce = useReducedMotion();
  const wrap = useRef<HTMLDivElement>(null);
  const globe = useRef<GlobeMethods | undefined>(undefined);
  const [width, setWidth] = useState(600);
  const [playing, setPlaying] = useState(!reduce);
  const [hover, setHover] = useState<Marker | null>(null);
  const [ready, setReady] = useState(false);
  const material = useMemo(makeGlobeMaterial, []);
  const wide = width >= 768; // overlay panels are hidden on small screens
  const left = wide ? inset : 0;
  const right = wide ? insetRight : 0;
  const gw = Math.max(200, width - left - right);
  const fit = Math.round(fitAltitude(gw, height, compact) * 20) / 20; // steps, so tiny resizes don't re-zoom
  const playingRef = useRef(playing);
  playingRef.current = playing;

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  // Lighting + glass shell, once the globe exists.
  useEffect(() => {
    const g = globe.current;
    if (!g || !ready) return;
    const ambient = new THREE.AmbientLight(0xffffff, 1.35);
    const key = new THREE.DirectionalLight(0xffffff, 1.7);
    key.position.set(-1.2, 1.1, 1.4);
    const fill = new THREE.DirectionalLight(0x9cc8ff, 0.6);
    fill.position.set(1, -0.6, 0.6);
    g.lights([ambient, key, fill]);
    const scene = g.scene();
    const r = g.getGlobeRadius();
    let clouds = scene.getObjectByName("netosis-clouds");
    if (!clouds) scene.add((clouds = cloudLayer(r * 1.005)));
    if (!scene.getObjectByName("netosis-glass")) scene.add(glassShell(r * 1.009));
    let raf = 0;
    const drift = () => {
      if (playingRef.current) clouds!.rotation.y += 0.00012;
      raf = requestAnimationFrame(drift);
    };
    if (!reduce) drift();
    return () => cancelAnimationFrame(raf);
  }, [ready, reduce]);

  useEffect(() => {
    const g = globe.current;
    if (!g || !ready) return;
    const c = g.controls();
    c.autoRotate = playing;
    c.autoRotateSpeed = 0.35;
    c.enableZoom = !compact;
    c.minDistance = 160;
    c.maxDistance = 100 * (1 + fit * 1.5);
  }, [playing, compact, ready, fit]);

  useEffect(() => {
    const r = REGIONS.find((x) => x.id === region) ?? REGIONS[0];
    globe.current?.pointOfView({ lat: r.lat, lng: r.lng, altitude: fit * r.alt }, reduce ? 0 : 1100);
  }, [region, reduce, ready, fit]);

  // Fly to a newly selected source once; data refreshes must not yank the camera back.
  const dataRef = useRef(data);
  dataRef.current = data;
  useEffect(() => {
    const p = dataRef.current?.points.find((x) => x.ip === selected);
    if (p) globe.current?.pointOfView({ lat: p.lat, lng: p.lng, altitude: fit * 0.82 }, reduce ? 0 : 900);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, reduce]);

  // One marker per location (several IPs can share a city).
  const points = useMemo(() => {
    const groups = new Map<string, Marker>();
    for (const p of (data?.points ?? []).filter((x) => inRegion(x, region))) {
      const key = `${p.lat.toFixed(2)},${p.lng.toFixed(2)}`;
      const g = groups.get(key);
      if (!g) {
        groups.set(key, { ...p, sources: [p] });
        continue;
      }
      g.sources.push(p);
      g.events += p.events;
      g.sessions += p.sessions;
      if (LEVEL[p.level].rank > LEVEL[g.level].rank) g.level = p.level;
      if (p.ip === selected) g.ip = p.ip;
    }
    return [...groups.values()];
  }, [data, region, selected]);

  const arcsRaw = useMemo(
    () =>
      points
        .filter((p) => p.arc && p.dest)
        .map((p) => {
          const c = SEV_COLOR[sevOf(p.level)];
          return { ...p, startLat: p.lat, startLng: p.lng, endLat: p.dest!.lat, endLng: p.dest!.lng, color: [hexA(c, 0.15), hexA(c, 0.95)] };
        }),
    [points],
  );
  const arcs = useStable(arcsRaw, (a) => `${a.lat},${a.lng},${a.level}`);

  // Arcs only end at a grounded destination: the configured lab, or the demo lab for demo data.
  const site = data?.site ?? (data?.points.some((p) => p.demo) ? data?.demo_site : null) ?? null;

  const ringsRaw = useMemo(() => {
    const r: { lat: number; lng: number; color: string; maxR: number; speed: number }[] = [];
    if (site) r.push({ lat: site.lat, lng: site.lng, color: SEV_COLOR.site, maxR: 4, speed: 1.6 });
    for (const p of points) {
      const sev = sevOf(p.level);
      if (sev !== "low") r.push({ lat: p.lat, lng: p.lng, color: SEV_COLOR[sev], maxR: sev === "high" ? 3.4 : 2.6, speed: 1.8 });
    }
    return r;
  }, [points, site]);
  const rings = useStable(ringsRaw, (r) => `${r.lat},${r.lng},${r.color}`);

  const markersRaw: Marker[] = useMemo(
    () => [
      ...points,
      ...(site
        ? [{ ...(site as object), ip: "site", isSite: true, level: "LOW", sources: [], events: 0 } as unknown as Marker]
        : []),
    ],
    [points, site],
  );
  // Marker key includes level + size so a sprite is only rebuilt when it must look different.
  const markers = useStable(markersRaw, (m) => `${m.lat},${m.lng},${m.level},${m.sources.length},${m.ip === selected}`);

  // Callouts like the reference: the selected/hovered source, else the two most severe.
  const calloutsRaw = useMemo(() => {
    const pick = points.find((p) => p.ip === selected) ?? hover;
    if (pick) return [{ ...pick, pinned: !!selected, side: "right" as const, chip: false }];
    if (compact) return [];
    // small labels on the busiest sources; the overlap check hides any that would collide
    return [...points]
      .sort((a, b) => LEVEL[b.level].rank - LEVEL[a.level].rank || b.events - a.events)
      .slice(0, 6)
      .map((p) => ({ ...p, pinned: false, side: "right" as const, chip: true }));
  }, [points, selected, hover, compact]);
  const callouts = useStable(calloutsRaw, (c) => `${c.ip},${c.pinned},${c.events},${c.level},${c.side},${c.chip}`);


  // Stable accessors: a new function each render makes three-globe re-digest the layer.
  const arcStroke = useCallback((d: object) => ((d as GeoPoint).ip === selected ? 0.9 : 0.45), [selected]);
  const arcGap = useCallback((d: object) => (hash((d as GeoPoint).ip) % 100) / 100, []);
  const markerObject = useCallback(
    (d: object) => {
      const m = d as Marker;
      const color = m.isSite ? SEV_COLOR.site : SEV_COLOR[sevOf(m.level)];
      const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTexture(color), transparent: true, depthWrite: false }));
      const size = m.isSite ? 9 : Math.min(11, 6 + Math.sqrt(m.sources.length) * 1.5) * (m.ip === selected ? 1.35 : 1);
      sprite.scale.set(size, size, 1);
      sprite.renderOrder = 3;
      return sprite;
    },
    [selected],
  );
  // Latest onSelect/selected without rebuilding the callout DOM on every render.
  const selectRef = useRef({ onSelect, selected });
  selectRef.current = { onSelect, selected };
  const picked = useRef(false);
  const pick = useCallback((m: Marker | null) => {
    picked.current = true;
    const { onSelect: cb, selected: cur } = selectRef.current;
    cb?.(m && m.ip !== cur ? m : null);
  }, []);
  const htmlEl = useCallback(
    (d: object) => {
      const c = d as Marker & { pinned: boolean; side: "right" | "left"; chip: boolean };
      return c.chip ? chipEl(c, (m) => pick(m)) : calloutEl(c, c.pinned, c.side, (m) => pick(m));
    },
    [pick],
  );
  // Click on empty space (globe surface or background) clears the selection; a drag doesn't.
  const down = useRef<{ x: number; y: number } | null>(null);
  // three-globe only says whether the point faces us; the overlap check below decides.
  const htmlVisible = useCallback((el: HTMLElement, visible: boolean) => {
    el.dataset.front = visible ? "1" : "0";
  }, []);

  // Never overlap: hide a card that is behind the globe, leaves the map area, or touches
  // an overlay (region list, legend, buttons) or a card already shown. Pinned goes first.
  const area = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const hit = (a: DOMRect, b: DOMRect, pad = 4) =>
      a.left < b.right + pad && a.right + pad > b.left && a.top < b.bottom + pad && a.bottom + pad > b.top;
    const tick = () => {
      const root = wrap.current;
      const box = area.current?.getBoundingClientRect();
      if (!root || !box) return;
      const scope = root.parentElement ?? root;
      const obstacles = [...scope.querySelectorAll<HTMLElement>("[data-globe-obstacle]")]
        .filter((o) => o.offsetParent !== null)
        .map((o) => o.getBoundingClientRect());
      const cards = [...root.querySelectorAll<HTMLElement>("[data-card]")].sort(
        (a, b) => Number(b.dataset.pinned === "1") - Number(a.dataset.pinned === "1"),
      );
      const shown: DOMRect[] = [];
      for (const card of cards) {
        const r = card.getBoundingClientRect();
        const front = card.parentElement?.dataset.front !== "0";
        const inside = r.left >= box.left + 4 && r.right <= box.right - 4 && r.top >= box.top + 4 && r.bottom <= box.bottom - 4;
        const ok = front && inside && !obstacles.some((o) => hit(r, o)) && !shown.some((o) => hit(r, o));
        card.style.opacity = ok ? "1" : "0";
        card.style.visibility = ok ? "visible" : "hidden";
        if (ok) shown.push(r);
      }
    };
    const id = window.setInterval(tick, 200);
    return () => window.clearInterval(id);
  }, []);
  const ringColor = useCallback((d: object) => (t: number) => hexA((d as { color: string }).color, 0.9 * (1 - t)), []);

  return (
    <div
      ref={wrap}
      className="relative w-full overflow-hidden select-none"
      onPointerDown={(e) => {
        down.current = { x: e.clientX, y: e.clientY };
        picked.current = false; // a fresh click: only a marker/card/arc hit sets this again
      }}
      onClick={(e) => {
        const d = down.current;
        const moved = d ? Math.hypot(e.clientX - d.x, e.clientY - d.y) > 5 : false;
        const onControl = (e.target as HTMLElement).closest("button, a");
        if (!picked.current && !moved && !onControl && selectRef.current.selected) selectRef.current.onSelect?.(null);
        picked.current = false;
      }}
      style={{
        height,
        background:
          "radial-gradient(ellipse 60% 70% at 50% 50%, rgba(147,197,253,.45) 0%, rgba(219,234,254,.55) 38%, rgba(248,250,252,0) 72%), #ffffff",
      }}
    >
      <div ref={area} className="absolute inset-y-0 overflow-hidden" style={{ left, right }}>
        <GlobeGL
          ref={globe}
          width={gw}
          height={height}
          backgroundColor="rgba(0,0,0,0)"
          globeMaterial={material}
          onGlobeReady={() => setReady(true)}
          showAtmosphere
          atmosphereColor="#7cc4ff"
          atmosphereAltitude={0.22}
          objectsData={markers}
          objectLat="lat"
          objectLng="lng"
          objectAltitude={0.012}
          objectThreeObject={markerObject}
          onObjectClick={(d: object) => {
            const m = d as Marker;
            if (!m.isSite) pick(m);
          }}
          onObjectHover={(d: object | null) => setHover(d && !(d as Marker).isSite ? (d as Marker) : null)}
          objectLabel={(d: object) => ((d as Marker).isSite ? `<b>${esc((d as Marker & { label?: string }).label ?? "Lab")}</b>` : "")}
          htmlElementsData={callouts}
          htmlLat="lat"
          htmlLng="lng"
          htmlAltitude={0.02}
          htmlElement={htmlEl}
          htmlElementVisibilityModifier={htmlVisible}
          arcsData={arcs}
          arcColor="color"
          arcStroke={arcStroke}
          arcAltitudeAutoScale={0.32}
          arcDashLength={0.5}
          arcDashGap={0.18}
          arcDashInitialGap={arcGap}
          arcDashAnimateTime={playing ? 2600 : 0}
          onArcClick={(d: object) => pick(d as Marker)}
          ringsData={playing ? rings : []}
          ringColor={ringColor}
          ringMaxRadius="maxR"
          ringPropagationSpeed="speed"
          ringRepeatPeriod={1500}
          ringAltitude={0.004}
          animateIn={!reduce}
        />
      </div>

      {!compact && (
        <div data-globe-obstacle className="absolute bottom-5 right-5 z-10 flex flex-col overflow-hidden rounded-xl border border-white/80 bg-white/75 shadow-md backdrop-blur-md">
          <GlobeBtn label="Zoom in" onClick={() => zoom(globe.current, 0.75)}>
            <Plus className="size-4" />
          </GlobeBtn>
          <GlobeBtn label="Zoom out" onClick={() => zoom(globe.current, 1.3)}>
            <Minus className="size-4" />
          </GlobeBtn>
          <GlobeBtn
            label="Reset view"
            onClick={() => {
              onSelect?.(null);
              const r = REGIONS.find((x) => x.id === region) ?? REGIONS[0];
              globe.current?.pointOfView({ lat: r.lat, lng: r.lng, altitude: fit * r.alt }, 800);
            }}
          >
            <LocateFixed className="size-4" />
          </GlobeBtn>
        </div>
      )}

      <button
        data-globe-obstacle
        className="btn absolute right-5 top-4 z-10 rounded-lg border border-white/80 bg-white/75 text-xs font-semibold shadow-xs backdrop-blur-md"
        onClick={() => setPlaying((p) => !p)}
        aria-pressed={!playing}
        aria-label={playing ? "Pause rotation and arc animation" : "Resume animation"}
      >
        {playing ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
        {playing ? "Pause" : "Resume"}
      </button>
    </div>
  );
}

function GlobeBtn({ children, label, onClick }: { children: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-label={label}
      title={label}
      className="grid size-9 place-items-center border-b border-line-2 text-ink-2 last:border-b-0 hover:bg-hover hover:text-ink transition-colors"
    >
      {children}
    </button>
  );
}

function zoom(g: GlobeMethods | undefined, factor: number) {
  if (!g) return;
  const pov = g.pointOfView();
  g.pointOfView({ ...pov, altitude: Math.min(4, Math.max(0.6, pov.altitude * factor)) }, 400);
}

function hexA(hex: string, a: number) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a.toFixed(3)})`;
}

function hash(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/** Honest footer: what's on the globe, what isn't, and why. */
export function GeoProvenance({ data }: { data: GeoData | undefined }) {
  if (!data) return null;
  const { internal, public_unmapped, reserved } = data.unmapped;
  const demoPts = data.points.filter((p) => p.demo).length;
  const parts: string[] = [];
  if (demoPts) parts.push(`${demoPts} demo source${demoPts > 1 ? "s" : ""} placed at illustrative locations`);
  if (internal) parts.push(`${internal} lab-internal source${internal > 1 ? "s" : ""} (private IPs are never mapped)`);
  if (public_unmapped)
    parts.push(
      `${public_unmapped} public source${public_unmapped > 1 ? "s" : ""} not geolocated${data.geodb.available ? "" : " — no GeoIP database installed"}`,
    );
  if (reserved) parts.push(`${reserved} reserved address${reserved > 1 ? "es" : ""}`);
  if (!data.site && data.points.some((p) => !p.demo)) parts.push("lab location not configured, so live arcs are hidden");
  if (!parts.length) parts.push("All sources in this window are mapped from IP location data (approximate)");
  return <p className="text-[11.5px] leading-snug text-ink-3">{parts.join(" · ")}.</p>;
}
