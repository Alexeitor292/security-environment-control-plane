// Real-DOM test harness for accessibility assertions.
//
// WHY THIS EXISTS. The enrollment suites render with `renderToStaticMarkup`, which is fast and
// deterministic but produces a STRING. A string cannot answer the questions that actually decide
// whether a keyboard user can operate a page: where focus is, what an `aria-*` idref resolves to,
// whether a control is in the tab order, and what an accessibility-tree walk finds. Two defects
// that shipped on this surface were of exactly that kind. This harness mounts the real component
// into a real document so those questions have real answers.
//
// It is test-only. It is never imported by application code, and `vite build` takes index.html as
// its only input, so it cannot reach a bundle.

import axe from "axe-core";
import { act, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

export interface Mounted {
  container: HTMLElement;
  root: Root;
  /** Run an interaction with React's batching and passive effects flushed before it returns. */
  run(fn: () => void): void;
  unmount(): void;
}

/**
 * Mount into `document.body`.
 *
 * Attaching to the live document rather than a detached node is load-bearing: `document.activeElement`,
 * `:focus-visible`, `element.focus()` and axe's own visibility checks all behave differently on a
 * detached tree, so a detached mount would quietly re-create the blind spot this harness exists to
 * remove.
 */
export function mount(element: ReactElement): Mounted {
  // React refuses to flush effects synchronously outside an act environment.
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  document.documentElement.lang = "en";

  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(element);
  });

  return {
    container,
    root,
    run(fn: () => void) {
      act(() => {
        fn();
      });
    },
    unmount() {
      act(() => {
        root.unmount();
      });
      container.remove();
    },
  };
}

/**
 * Rules deliberately not run here, and why. Stated as data so the exclusion is visible in the
 * source rather than buried in a config object, and so a reader can see exactly how much of the
 * accessibility claim is machine-checked.
 */
export const RULES_NOT_MACHINE_CHECKED: ReadonlyArray<readonly [string, string]> = [
  [
    "color-contrast",
    // jsdom has no layout and no canvas, so axe cannot sample a rendered pixel. Contrast is held
    // instead by the CSS token discipline the stylesheets state and follow — semantic tokens only,
    // and never --ink-muted for text — and is verified by eye in a browser, in both themes.
    "requires real layout and a canvas; not available in jsdom",
  ],
  [
    "region",
    // A best-practice rule about page-level landmarks. The component is mounted on its own here,
    // outside the application shell that provides <main>, so the rule would be answering a question
    // about the harness rather than about the component.
    "page-level landmark rule; the component is mounted outside the app shell",
  ],
];

const DISABLED = Object.fromEntries(
  RULES_NOT_MACHINE_CHECKED.map(([rule]) => [rule, { enabled: false }]),
);

/**
 * Run axe-core over a mounted subtree and return the violations.
 *
 * Returns them rather than asserting, so each suite can assert with its own message and so a
 * caller can legitimately narrow the scope. `resultTypes` keeps the payload to violations only —
 * a full axe result is large enough to bury the failure it is reporting.
 */
export async function axeViolations(
  container: HTMLElement,
): Promise<axe.Result[]> {
  const results = await axe.run(container, {
    runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"],
    rules: DISABLED,
    resultTypes: ["violations"],
  });
  return results.violations;
}

/** A readable one-line summary per violation, for an assertion message that names the defect. */
export function describeViolations(violations: axe.Result[]): string[] {
  return violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.length} node(s)) -> ${v.nodes[0]?.html ?? ""}`,
  );
}

/** Every element the keyboard can reach, in document order. */
export function tabbable(container: HTMLElement): HTMLElement[] {
  const candidates = container.querySelectorAll<HTMLElement>(
    "a[href], button, input, select, textarea, summary, [tabindex]",
  );
  return [...candidates].filter((el) => {
    if (el.hasAttribute("disabled")) return false;
    const index = el.getAttribute("tabindex");
    if (index !== null && Number(index) < 0) return false;
    return el.closest("[hidden]") === null;
  });
}
