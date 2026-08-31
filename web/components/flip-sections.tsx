"use client";

// Section flip (§10.1). The views are server-rendered; this component only
// switches which one is visible. Fragments never drive the switch on
// click, so the viewport does not move: the URL is updated with
// history.replaceState (shareable, no scroll), and a fragment present at
// load selects the matching view after hydration.

import { useEffect, useState } from "react";

export interface FlipView {
  id: string;
  label: string;
  content: React.ReactNode;
}

function FlipButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className="rounded-md px-4 py-2 text-sm font-medium"
      style={
        active
          ? { background: "var(--color-accent)", color: "var(--color-accent-fg)" }
          : { border: "1px solid var(--color-border)", color: "var(--color-fg)" }
      }
    >
      {label}
    </button>
  );
}

export default function FlipSections({
  views,
  initial,
}: {
  views: FlipView[];
  initial?: string;
}) {
  const ids = views.map((v) => v.id);
  const [active, setActive] = useState<string>(initial && ids.includes(initial) ? initial : ids[0]);

  useEffect(() => {
    // Deep link: honour a fragment already in the URL (someone followed a
    // shared link) without scrolling anywhere.
    const hash = window.location.hash.replace(/^#/, "");
    if (ids.includes(hash)) {
      setActive(hash);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function flip(next: string) {
    setActive(next);
    // Keep the URL truthful for copy/sharing; replaceState does not scroll.
    window.history.replaceState(window.history.state, "", "#" + next);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-3">
        {views.map((v) => (
          <FlipButton key={v.id} label={v.label} active={active === v.id} onClick={() => flip(v.id)} />
        ))}
      </div>
      {views.map((v) => (
        <div key={v.id} hidden={active !== v.id}>
          {v.content}
        </div>
      ))}
    </div>
  );
}
