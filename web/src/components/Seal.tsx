/**
 * The issuing seal. Concentric rings around a keyway, in foil.
 *
 * It is the only place the brand appears, and the only large use of gold on the page —
 * everything else stays in ink so the seal reads as the mark of authority it is meant to be.
 */
export function Seal({ className, title }: { className?: string; title?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 64 64"
      role={title ? "img" : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      focusable="false"
    >
      <defs>
        <linearGradient id="seal-foil" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--foil-bright)" />
          <stop offset="48%" stopColor="var(--foil)" />
          <stop offset="100%" stopColor="var(--foil-deep)" />
        </linearGradient>
      </defs>

      {/* Milled edge: 48 teeth, the way a struck seal is knurled. */}
      <g stroke="url(#seal-foil)" strokeWidth="1.6" opacity="0.85">
        {Array.from({ length: 48 }, (_, i) => {
          const angle = (i / 48) * Math.PI * 2;
          const inner = 26.5;
          const outer = 30.5;
          return (
            <line
              key={i}
              x1={32 + Math.cos(angle) * inner}
              y1={32 + Math.sin(angle) * inner}
              x2={32 + Math.cos(angle) * outer}
              y2={32 + Math.sin(angle) * outer}
            />
          );
        })}
      </g>

      <circle cx="32" cy="32" r="25" fill="none" stroke="url(#seal-foil)" strokeWidth="2" />
      <circle cx="32" cy="32" r="20.5" fill="none" stroke="url(#seal-foil)" strokeWidth="0.8" opacity="0.7" />

      {/* Keyway: a warded bit, the oldest mark for "this opens only with the right key". */}
      <g fill="url(#seal-foil)">
        <circle cx="32" cy="26" r="5.6" />
        <path d="M29.4 30h5.2l-1 14.5h-3.2z" />
        <rect x="34.4" y="34" width="4.6" height="2.4" rx="0.6" />
        <rect x="34.4" y="38.4" width="3.4" height="2.4" rx="0.6" />
      </g>
      <circle cx="32" cy="26" r="2.2" fill="var(--ink-900)" />
    </svg>
  );
}
