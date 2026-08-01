/**
 * DEV-ONLY measured contrast probe. Not imported by anything; not shipped.
 *
 * WHY IT EXISTS. Rendered colour contrast is the one accessibility property neither test suite can
 * reach: `renderToStaticMarkup` has no colours at all, and jsdom has no layout and no canvas, so
 * axe-core skips its `color-contrast` rule there. That left "contrast is held by the token
 * discipline" as an argument rather than a measurement. This makes it a measurement, and a
 * repeatable one — the same numbers come out every run, so a regression is visible rather than
 * felt.
 *
 * WHAT IT DOES. Walks every element that owns a text node, resolves the effective background by
 * compositing up the ancestor chain (a translucent surface over a surface is computed, not
 * guessed), and reports every pair below its WCAG 2.1 AA threshold — 4.5:1 for body text, 3:1 for
 * large text, per the same size/weight rule axe uses.
 *
 * HOW TO RUN. Start the dev server, open the harness in a browser, and paste this file into the
 * devtools console — or drive it with Playwright's `evaluate`. Both surfaces, both themes:
 *
 *   /a11y-harness.html                       (worker enrollment, dark)
 *   /a11y-harness.html?theme=light
 *   /a11y-harness.html?view=inventory
 *   /a11y-harness.html?view=inventory&theme=light
 *
 * WHAT IT IS NOT. It is not a substitute for looking: it measures text against its background and
 * says nothing about focus-ring visibility, non-text contrast, or whether a layout is legible.
 * Those still need eyes.
 */

/* eslint-disable */
(function contrastProbe(rootSelector) {
  const parse = (value) => {
    const match = value.match(/rgba?\(([^)]+)\)/);
    if (!match) return null;
    const parts = match[1].split(",").map(Number);
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const channel = (v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  const luminance = (c) =>
    0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
  const composite = (fg, bg) => ({
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a),
    a: 1,
  });
  // The effective background: the first ancestor with a non-transparent background, composited
  // over ITS background when it is itself translucent.
  const backgroundOf = (el) => {
    let node = el;
    while (node && node !== document.documentElement) {
      const colour = parse(getComputedStyle(node).backgroundColor);
      if (colour && colour.a > 0) {
        return colour.a < 1 ? composite(colour, backgroundOf(node.parentElement)) : colour;
      }
      node = node.parentElement;
    }
    const root = parse(getComputedStyle(document.documentElement).backgroundColor);
    return root && root.a > 0 ? root : { r: 255, g: 255, b: 255, a: 1 };
  };
  const ratio = (a, b) => {
    const first = luminance(a);
    const second = luminance(b);
    return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
  };

  const root = document.querySelector(rootSelector || ".wenr");
  if (!root) return { error: `no element matches ${rootSelector}` };

  const failures = [];
  let measured = 0;
  for (const el of root.querySelectorAll("*")) {
    const ownsText = [...el.childNodes].some(
      (node) => node.nodeType === 3 && node.textContent.trim().length > 0,
    );
    if (!ownsText) continue;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none") continue;
    // Screen-reader-only text is positioned off-screen and is never seen; measuring it would
    // report failures no sighted user can encounter.
    if (el.closest(".ui-sr-only")) continue;
    const foreground = parse(style.color);
    if (!foreground) continue;
    measured += 1;
    const background = backgroundOf(el);
    const size = parseFloat(style.fontSize);
    const bold = parseInt(style.fontWeight, 10) >= 700;
    const large = size >= 24 || (size >= 18.66 && bold);
    const required = large ? 3.0 : 4.5;
    const measuredRatio = ratio(
      foreground.a < 1 ? composite(foreground, background) : foreground,
      background,
    );
    if (measuredRatio < required) {
      failures.push({
        className: String(el.className).slice(0, 48),
        text: (el.textContent || "").trim().slice(0, 48),
        ratio: Math.round(measuredRatio * 100) / 100,
        required,
      });
    }
  }
  return {
    theme: document.documentElement.getAttribute("data-theme") || "dark",
    measured,
    failures,
  };
})(".einv, .wenr");
