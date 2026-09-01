// The site's two typefaces, self-hosted (font-src 'self' in the CSP, no
// request leaves the origin). IBM Plex Sans and Plex Mono are drawn as one
// family, which matters on pages that are half identifiers: a version, a
// digest, or a capability set in mono sits on the same baseline and weight
// as the prose around it. Latin subset, OFL-licensed.
import localFont from "next/font/local";

export const plexSans = localFont({
  src: [
    { path: "./fonts/IBMPlexSans-var.woff2", weight: "400 600", style: "normal" },
    { path: "./fonts/IBMPlexSans-italic.woff2", weight: "400", style: "italic" },
  ],
  variable: "--font-plex-sans",
  display: "swap",
  fallback: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
});

export const plexMono = localFont({
  src: [
    { path: "./fonts/IBMPlexMono-400.woff2", weight: "400", style: "normal" },
    { path: "./fonts/IBMPlexMono-500.woff2", weight: "500", style: "normal" },
  ],
  variable: "--font-plex-mono",
  display: "swap",
  fallback: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", "monospace"],
});
