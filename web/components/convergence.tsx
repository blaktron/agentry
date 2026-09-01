// Convergence: the home-page graphic. Five beams of light — one per part of
// a BriefAgent that Agentry keeps separate at run time — travel from their
// own sources and meet in a single output. Pure SVG + CSS keyframes (in
// globals.css), so it costs no JavaScript and the strict CSP is untouched;
// the animations stop under prefers-reduced-motion and the still frame
// reads on its own.
//
// Geometry: sources fan out on the left, beams are cubic curves that all
// pass through the focus at (400, 180), and one bright beam leaves it to
// the right. Each beam has a soft blurred copy underneath for the glow, the
// stroke itself, and a short "spark" that runs along the path — the beams
// pulse on staggered delays so the eye never sees them in lockstep, and the
// output pulses on the shared period as the sum of them.

const FOCUS = { x: 400, y: 180 };

const SOURCES: { label: string; x: number; y: number; color: string; delay: number }[] = [
  { label: "manifest", x: 40, y: 48, color: "var(--color-accent)", delay: 0 },
  { label: "instructions", x: 24, y: 114, color: "#38bdf8", delay: 1.4 },
  { label: "tools", x: 16, y: 180, color: "#a78bfa", delay: 2.8 },
  { label: "policy", x: 24, y: 246, color: "#fbbf24", delay: 4.2 },
  { label: "secrets", x: 40, y: 312, color: "#fb7185", delay: 5.6 },
];

function beamPath(x: number, y: number): string {
  // Two control points: the first pulls the beam out horizontally from its
  // source, the second lands it into the focus along the same tangent so
  // the five curves arrive as one bundle rather than crossing.
  const c1x = x + 150;
  const c2x = FOCUS.x - 110;
  return `M ${x} ${y} C ${c1x} ${y}, ${c2x} ${FOCUS.y}, ${FOCUS.x} ${FOCUS.y}`;
}

export function Convergence({ className = "" }: { className?: string }) {
  const outputPath = `M ${FOCUS.x} ${FOCUS.y} L 476 ${FOCUS.y}`;
  return (
    <svg
      viewBox="0 0 480 360"
      role="img"
      aria-label="Five beams of light — a BriefAgent's manifest, instructions, tools, policy, and secrets — travel from separate sources and converge into a single output."
      className={`convergence h-auto w-full ${className}`}
    >
      <title>Separate parts, one output</title>
      <defs>
        <filter id="cv-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="4" />
        </filter>
        <filter id="cv-glow-wide" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="9" />
        </filter>
        <radialGradient id="cv-focus">
          <stop offset="0" stopColor="#ffffff" stopOpacity="0.95" />
          <stop offset="0.45" stopColor="var(--color-accent)" stopOpacity="0.55" />
          <stop offset="1" stopColor="var(--color-accent)" stopOpacity="0" />
        </radialGradient>
      </defs>

      {SOURCES.map((s) => {
        const d = beamPath(s.x, s.y);
        const style = { animationDelay: `${s.delay}s` } as React.CSSProperties;
        return (
          <g key={s.label}>
            {/* glow, beam, spark */}
            <path d={d} className="cv-beam cv-beam-glow" style={{ ...style, stroke: s.color }} filter="url(#cv-glow)" />
            <path d={d} className="cv-beam" style={{ ...style, stroke: s.color }} />
            <path d={d} className="cv-spark" style={{ ...style, stroke: s.color }} />
            {/* source node + label */}
            <circle cx={s.x} cy={s.y} r="7" className="cv-node-glow" style={{ ...style, fill: s.color }} filter="url(#cv-glow)" />
            <circle cx={s.x} cy={s.y} r="3.2" className="cv-node" style={{ ...style, fill: s.color }} />
            <text
              x={s.x + 12}
              y={s.y - 9}
              className="cv-label"
              style={{ fill: "var(--color-muted)" }}
            >
              {s.label}
            </text>
          </g>
        );
      })}

      {/* the output: one beam, one node, brighter than any input */}
      <path d={outputPath} className="cv-out cv-out-glow" filter="url(#cv-glow-wide)" />
      <path d={outputPath} className="cv-out" />
      <circle cx={FOCUS.x} cy={FOCUS.y} r="26" fill="url(#cv-focus)" className="cv-focus" />
      <circle cx={FOCUS.x} cy={FOCUS.y} r="4" style={{ fill: "#ffffff" }} />
      <text
        x={FOCUS.x}
        y={FOCUS.y + 34}
        textAnchor="middle"
        className="cv-label"
        style={{ fill: "var(--color-muted)" }}
      >
        one result, one receipt
      </text>
    </svg>
  );
}
