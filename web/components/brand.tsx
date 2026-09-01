// The Agentry mark and wordmark, inline so they take the page's own tokens
// (public/brand/*.svg carry their own media query for use outside the app —
// the directory service's sign-in page, for one). Same geometry as
// app/icon.svg: a shield with a check.
export function Mark({ size = 22, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      viewBox="0 0 48 48"
      width={size}
      height={size}
      aria-hidden="true"
      className={className}
      style={{ flex: "none" }}
    >
      <path
        d="M24 3 41 10.5 V 23 C 41 34.5 34 42.5 24 46.5 C 14 42.5 7 34.5 7 23 V 10.5 Z"
        style={{ fill: "var(--color-accent)" }}
      />
      <path
        d="M15.5 24.5 L 21.5 30.5 L 32.5 18.5"
        style={{ fill: "none", stroke: "var(--color-bg)", strokeWidth: 4, strokeLinecap: "round", strokeLinejoin: "round" }}
      />
    </svg>
  );
}

export function Wordmark({ brand }: { brand: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <Mark />
      <span className="text-lg font-semibold tracking-tight">{brand}</span>
    </span>
  );
}
