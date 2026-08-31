"use client";

// Home-page section flip (§10.1). The three views are server-rendered; this
// component only switches which one is visible. Fragments never drive the
// switch on click, so the viewport does not move: the URL is updated with
// history.replaceState (shareable, no scroll), and a fragment present at
// load selects the matching view after hydration.

import { useEffect, useState } from "react";

const VIEWS = ["what-briefagent", "how-scanning", "browse"] as const;
type View = (typeof VIEWS)[number];

const LABELS: Record<View, string> = {
  "what-briefagent": "What is a BriefAgent",
  "how-scanning": "How scanning works",
  browse: "Browse BriefAgents",
};

function FlipButton({
  view,
  active,
  onFlip,
}: {
  view: View;
  active: boolean;
  onFlip: (v: View) => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={() => onFlip(view)}
      className="rounded-md px-4 py-2 text-sm font-medium"
      style={
        active
          ? { background: "var(--color-accent)", color: "var(--color-accent-fg)" }
          : { border: "1px solid var(--color-border)", color: "var(--color-fg)" }
      }
    >
      {LABELS[view]}
    </button>
  );
}

export default function HomeFlip({
  what,
  scanning,
  browse,
}: {
  what: React.ReactNode;
  scanning: React.ReactNode;
  browse: React.ReactNode;
}) {
  const [view, setView] = useState<View>("what-briefagent");

  useEffect(() => {
    // Deep link: honour a fragment already in the URL (someone followed a
    // shared link) without scrolling anywhere.
    const hash = window.location.hash.replace(/^#/, "");
    if ((VIEWS as readonly string[]).includes(hash)) {
      setView(hash as View);
    }
  }, []);

  function flip(next: View) {
    setView(next);
    // Keep the URL truthful for copy/sharing; replaceState does not scroll.
    window.history.replaceState(window.history.state, "", "#" + next);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-3">
        {VIEWS.map((v) => (
          <FlipButton key={v} view={v} active={view === v} onFlip={flip} />
        ))}
      </div>
      <div hidden={view !== "what-briefagent"}>{what}</div>
      <div hidden={view !== "how-scanning"}>{scanning}</div>
      <div hidden={view !== "browse"}>{browse}</div>
    </div>
  );
}
