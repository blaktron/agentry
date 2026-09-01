"use client";

// Last-resort boundary: catches failures in the root layout itself, where
// app/error.tsx cannot run because the layout that would wrap it is what
// broke. It therefore has to supply its own <html>/<body>, and cannot rely
// on globals.css having been applied — hence the inline styles and the
// system palette rather than the design tokens.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: "ui-sans-serif, system-ui, -apple-system, sans-serif",
          maxWidth: "40rem",
          margin: "48px auto",
          padding: "0 16px",
          colorScheme: "light dark",
        }}
      >
        <main>
          <h1 style={{ fontSize: "20px", margin: "0 0 12px" }}>Agentry is not able to render this page</h1>
          <p style={{ margin: "0 0 12px", lineHeight: 1.6 }}>
            The console itself failed, not just the page you asked for. Nothing was changed by the
            request that failed.
          </p>
          {error.digest && (
            <p style={{ margin: "0 0 12px", fontSize: "13px" }}>
              Reference <code>{error.digest}</code>
            </p>
          )}
          <p>
            <button type="button" onClick={reset} style={{ padding: "6px 12px" }}>
              Try again
            </button>{" "}
            <a href="/">Go to the home page</a>
          </p>
        </main>
      </body>
    </html>
  );
}
