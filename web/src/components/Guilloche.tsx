import { useMemo } from "react";

/**
 * Guilloche linework, generated rather than drawn.
 *
 * Real banknotes and passports use a geometric lathe to cut interlocking hypotrochoid
 * curves: the pattern is hard to reproduce by hand or by photocopier, which is exactly
 * why it signals authenticity. These paths come from the same parametric family
 *
 *     x = (R - r)·cos t + d·cos(((R - r) / r)·t)
 *     y = (R - r)·sin t - d·sin(((R - r) / r)·t)
 *
 * so the ornament on the card is produced the way the real thing is, not traced.
 */

function gcd(a: number, b: number): number {
  return b === 0 ? a : gcd(b, a % b);
}

function hypotrochoid(R: number, r: number, d: number, steps = 720): string {
  // The curve closes after r / gcd(R, r) revolutions.
  const turns = r / gcd(Math.round(R), Math.round(r));
  const total = Math.PI * 2 * turns;
  const points: string[] = [];
  for (let i = 0; i <= steps; i += 1) {
    const t = (i / steps) * total;
    const k = (R - r) / r;
    const x = (R - r) * Math.cos(t) + d * Math.cos(k * t);
    const y = (R - r) * Math.sin(t) - d * Math.sin(k * t);
    points.push(`${x.toFixed(2)},${y.toFixed(2)}`);
  }
  return `M${points.join("L")}Z`;
}

type Rosette = { R: number; r: number; d: number; opacity: number; width: number; colour: string };

const LAYERS: Rosette[] = [
  { R: 100, r: 31, d: 68, opacity: 0.85, width: 0.45, colour: "var(--rule)" },
  { R: 86, r: 23, d: 52, opacity: 0.7, width: 0.4, colour: "var(--rule)" },
  { R: 62, r: 17, d: 40, opacity: 0.8, width: 0.4, colour: "var(--foil-deep)" },
  { R: 40, r: 11, d: 26, opacity: 0.55, width: 0.35, colour: "var(--rule)" },
];

export function Guilloche({ className }: { className?: string }) {
  const paths = useMemo(
    () => LAYERS.map((layer) => ({ ...layer, d: hypotrochoid(layer.R, layer.r, layer.d) })),
    [],
  );

  return (
    <svg
      className={className}
      viewBox="-130 -130 260 260"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <g fill="none" strokeLinejoin="round">
        {paths.map((layer, index) => (
          <path
            key={index}
            d={layer.d}
            stroke={layer.colour}
            strokeWidth={layer.width}
            opacity={layer.opacity}
            vectorEffect="non-scaling-stroke"
          />
        ))}
      </g>
    </svg>
  );
}
