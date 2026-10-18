import type { Level } from "../lib/api";

// Light theme: a soft field tinted by risk, the figure in deep ink.
const FIELD: Record<Level, string> = {
  LOW: "#e2f5ee",
  MEDIUM: "#e3ecfd",
  HIGH: "#fdf0d9",
  CRITICAL: "#fde3e6",
};
const INK = "#14243a";
const INK2 = "#5b6b82";

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * A person, drawn in code. Same address -> same face. What they wear comes
 * from their behaviour (persona), the backdrop tint from their risk level.
 */
export function Avatar({
  seed,
  persona,
  level,
  size = 96,
  title,
}: {
  seed: string;
  persona: string;
  level: Level;
  size?: number;
  title?: string;
}) {
  const h = hash(seed);
  const field = FIELD[level];
  const sw = 64 + (h % 14); // shoulder width
  const headR = 16 + ((h >> 4) % 4);
  const lean = ((h >> 8) % 5) - 2; // slight head offset so no two look stamped
  const cx = 50 + lean;
  const hair = (h >> 12) % 4;
  const bot = persona === "brute_forcer";

  const body = (
    <path
      d={`M ${50 - sw / 2} 100 L ${50 - sw / 2} 88 Q ${50 - sw / 2} 70 36 66 L 64 66 Q ${50 + sw / 2} 70 ${50 + sw / 2} 88 L ${50 + sw / 2} 100 Z`}
      fill={INK}
    />
  );

  let head: React.ReactNode;
  if (bot) {
    head = (
      <>
        <rect x="47.5" y="14" width="5" height="12" fill={INK2} />
        <rect x="45" y="10" width="10" height="7" fill={INK} />
        <rect x="32" y="26" width="36" height="36" fill={INK} />
        <rect x="39" y="38" width="7" height="7" fill={field} />
        <rect x="54" y="38" width="7" height="7" fill={field} />
        <rect x="40" y="51" width="20" height="4" fill={field} />
        <rect x="46" y="62" width="8" height="8" fill={INK2} />
      </>
    );
  } else {
    const face = (
      <>
        <rect x="44" y="58" width="12" height="12" fill={INK} />
        <circle cx={cx} cy="44" r={headR} fill={INK} />
      </>
    );
    const eyes = (
      <>
        <rect x={cx - 9} y="42" width="4" height="4.5" fill={field} />
        <rect x={cx + 5} y="42" width="4" height="4.5" fill={field} />
      </>
    );
    switch (persona) {
      case "lateral_mover": // hood up, face in shadow
        head = (
          <>
            <path d={`M 26 72 Q 22 22 50 18 Q 78 22 74 72 Z`} fill={INK2} />
            <ellipse cx={cx} cy="46" rx="14" ry="16" fill={field} />
            <rect x={cx - 8} y="43" width="4" height="4" fill={INK} />
            <rect x={cx + 4} y="43" width="4" height="4" fill={INK} />
          </>
        );
        break;
      case "credential_hunter": // balaclava with an eye slit
        head = (
          <>
            {face}
            <rect x={cx - headR + 1} y="35" width={(headR - 1) * 2} height={headR + 6} fill={INK2} />
            <rect x={cx - 11} y="41" width="22" height="6" fill={field} />
            <rect x={cx - 8} y="43" width="4" height="3" fill={INK} />
            <rect x={cx + 4} y="43" width="4" height="3" fill={INK} />
          </>
        );
        break;
      case "dropper": // cap with a brim
        head = (
          <>
            {face}
            {eyes}
            <path d={`M ${cx - headR - 1} 40 Q ${cx} ${44 - headR - 8} ${cx + headR + 1} 40 Z`} fill={INK2} />
            <rect x={cx + 2} y="38" width={headR + 6} height="4.5" fill={INK2} />
          </>
        );
        break;
      case "persistence": // glasses, hair
        head = (
          <>
            {face}
            <path d={`M ${cx - headR} 42 Q ${cx} ${40 - headR - 6} ${cx + headR} 42 L ${cx + headR} 36 Q ${cx} ${30 - headR} ${cx - headR} 36 Z`} fill={INK2} />
            <rect x={cx - 12} y="40" width="10" height="7" fill={field} />
            <rect x={cx + 2} y="40" width="10" height="7" fill={field} />
            <rect x={cx - 3} y="42" width="6" height="2.4" fill={field} />
          </>
        );
        break;
      case "cleaner": // face mask
        head = (
          <>
            {face}
            {eyes}
            <rect x={cx - headR + 2} y="48" width={(headR - 2) * 2} height="11" fill={INK2} />
            <rect x={cx - 3} y="52" width="6" height="2" fill={field} />
          </>
        );
        break;
      case "explorer": // headphones
        head = (
          <>
            {face}
            {eyes}
            <path d={`M ${cx - headR - 3} 46 Q ${cx - headR - 3} ${22} ${cx} 22 Q ${cx + headR + 3} 22 ${cx + headR + 3} 46`} fill="none" stroke={INK2} strokeWidth="4.5" />
            <rect x={cx - headR - 7} y="42" width="8" height="14" fill={INK2} />
            <rect x={cx + headR - 1} y="42" width="8" height="14" fill={INK2} />
          </>
        );
        break;
      case "scanner": // headset with a mic
        head = (
          <>
            {face}
            {eyes}
            <path d={`M ${cx - headR - 2} 44 Q ${cx - headR - 2} 24 ${cx} 24 Q ${cx + headR + 2} 24 ${cx + headR + 2} 44`} fill="none" stroke={INK2} strokeWidth="4" />
            <rect x={cx - headR - 6} y="41" width="7" height="12" fill={INK2} />
            <path d={`M ${cx - headR - 3} 53 Q ${cx - headR} 62 ${cx - 4} 58`} fill="none" stroke={INK2} strokeWidth="3" />
          </>
        );
        break;
      default: {
        // opportunist: plain, with one of four hairlines picked by the seed
        const hairShapes = [
          null,
          <path key="a" d={`M ${cx - headR} 42 Q ${cx} ${40 - headR - 6} ${cx + headR} 42 L ${cx + headR} 38 Q ${cx} ${32 - headR} ${cx - headR} 38 Z`} fill={INK2} />,
          <path key="b" d={`M ${cx - headR - 1} 52 L ${cx - headR - 1} 36 Q ${cx} ${22 - headR / 2} ${cx + headR + 1} 36 L ${cx + headR + 1} 52 L ${cx + headR - 4} 52 L ${cx + headR - 4} 38 Q ${cx} 28 ${cx - headR + 4} 38 L ${cx - headR + 4} 52 Z`} fill={INK2} />,
          <path key="c" d={`M ${cx - headR} 40 Q ${cx} ${30 - headR} ${cx + headR} 40 Z`} fill={INK2} />,
        ];
        head = (
          <>
            {face}
            {eyes}
            {hairShapes[hair]}
          </>
        );
      }
    }
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      role="img"
      aria-label={title ?? `${persona} attacker`}
      style={{ display: "block", flex: "none" }}
      shapeRendering="geometricPrecision"
    >
      <rect width="100" height="100" fill={field} />
      {body}
      {head}
    </svg>
  );
}
