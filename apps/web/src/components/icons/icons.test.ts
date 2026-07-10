import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";

import { SECP_ICONS, providerIconName, type SecpIconName } from "./registry";

const REQUIRED: SecpIconName[] = [
  "secp-mark", "overview", "target", "proxmox", "kubernetes", "cloud-provider",
  "local-hosting", "worker", "resolver", "sealed-lock", "authorization",
  "endpoint-binding", "evidence", "candidate-plan", "immutable-hash",
  "audit-ledger", "staging-lab", "deployment", "topology", "packet", "firewall",
  "router", "switch", "vm", "container", "storage", "network-segment", "team",
  "approval", "refused", "rollback", "teardown",
];

describe("SECP icon registry", () => {
  it("contains every required product icon", () => {
    for (const name of REQUIRED) {
      expect(SECP_ICONS[name], name).toBeTypeOf("function");
    }
  });

  it("has no duplicate names and matches the required set exactly", () => {
    const names = Object.keys(SECP_ICONS);
    expect(new Set(names).size).toBe(names.length);
    expect(new Set(names)).toEqual(new Set(REQUIRED));
  });

  it("renders each icon as an SVG using currentColor and no raw color literals", () => {
    for (const name of REQUIRED) {
      const svg = renderToStaticMarkup(createElement(SECP_ICONS[name], {}));
      expect(svg, name).toContain("<svg");
      expect(svg, name).toContain('stroke="currentColor"');
      // no baked hex/rgb palette in the artwork
      expect(svg, name).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
      expect(svg, name).not.toMatch(/rgb\(/);
    }
  });

  it("is decorative (aria-hidden) by default and labeled when a title is given", () => {
    const decorative = renderToStaticMarkup(createElement(SECP_ICONS.target, {}));
    expect(decorative).toContain('aria-hidden="true"');
    const labeled = renderToStaticMarkup(
      createElement(SECP_ICONS.target, { title: "Execution target" }),
    );
    expect(labeled).toContain('role="img"');
    expect(labeled).toContain("<title>Execution target</title>");
    expect(labeled).not.toContain('aria-hidden="true"');
  });

  it("carries no private-key / secret-looking or decorative text in the artwork", () => {
    for (const name of REQUIRED) {
      const svg = renderToStaticMarkup(createElement(SECP_ICONS[name], {}));
      expect(svg.toLowerCase()).not.toContain("private key");
      expect(svg.toLowerCase()).not.toContain("secret");
      expect(svg).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY/);
      // no fabricated IPs baked into paths
      expect(svg).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    }
  });
});

describe("providerIconName", () => {
  it("maps known plugins to neutral glyphs and unknown to target", () => {
    expect(providerIconName("proxmox")).toBe("proxmox");
    expect(providerIconName("kubernetes")).toBe("kubernetes");
    expect(providerIconName("aws")).toBe("cloud-provider");
    expect(providerIconName("local")).toBe("local-hosting");
    expect(providerIconName("something-else")).toBe("target");
    expect(providerIconName(null)).toBe("target");
  });
});
