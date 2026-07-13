import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import type { PlanEnvironmentVersionBinding, VersionPublicationProvenance } from "../api/types";
import { PlanBindingCard } from "./PlanApproval";

// Static-render (server) tests for the plan review's environment-version binding card
// (ADR-016 PR E). Node-env convention (no jsdom); complements the pure-logic tests for
// planBindingView. These assert the surfaced structure, the deep-link, and — critically —
// that a legacy binding never shows published provenance and the card carries no mutation.

const PROV: VersionPublicationProvenance = {
  topology_document_id: "doc-1",
  topology_revision_id: "rev-1",
  topology_content_hash: "sha256:" + "a".repeat(64),
  topology_validation_result_id: "val-1",
  topology_validation_result_hash: "sha256:" + "b".repeat(64),
  base_environment_version_id: "base-9",
  publication_contract_version: "secp.publication/v1",
  publication_fingerprint: "sha256:" + "f".repeat(64),
};

function binding(over: Partial<PlanEnvironmentVersionBinding> = {}): PlanEnvironmentVersionBinding {
  return {
    environment_version_id: "ver-1",
    template_id: "tmpl-1",
    version_number: 3,
    api_version: "controlplane.security/v1alpha2",
    content_hash: "sha256:" + "c".repeat(64),
    publication_provenance: null,
    ...over,
  };
}

function html(b: PlanEnvironmentVersionBinding): string {
  return renderToStaticMarkup(
    createElement(MemoryRouter, null, createElement(PlanBindingCard, { binding: b })),
  );
}

describe("PlanBindingCard — published binding", () => {
  const out = html(binding({ publication_provenance: PROV }));

  it("labels the origin as published from an approved topology", () => {
    expect(out).toContain("Published from approved topology");
    expect(out).not.toContain("Legacy/manual immutable version");
  });

  it("surfaces the exact version fields (number, api version)", () => {
    expect(out).toContain("Version number");
    expect(out).toContain("controlplane.security/v1alpha2");
  });

  it("renders the server-owned publication provenance", () => {
    expect(out).toContain("Publication provenance (server-owned)");
    expect(out).toContain("Publication fingerprint");
    expect(out).toContain("Base version");
  });

  it("deep-links into the Environment Library at the exact template + version", () => {
    expect(out).toContain("/templates?template=tmpl-1&amp;version=ver-1");
    expect(out).toContain("Open in Environment Library");
  });

  it("carries no deploy/mutation control", () => {
    for (const forbidden of ["Deploy", "Submit for approval", "Approve", "Reject", "<button"]) {
      expect(out).not.toContain(forbidden);
    }
  });
});

describe("PlanBindingCard — legacy/manual binding", () => {
  const out = html(binding({ api_version: "controlplane.security/v1alpha1", publication_provenance: null }));

  it("labels the origin as a legacy/manual immutable version", () => {
    expect(out).toContain("Legacy/manual immutable version");
    expect(out).not.toContain("Published from approved topology");
  });

  it("shows NO publication provenance for a legacy version", () => {
    expect(out).not.toContain("Publication provenance (server-owned)");
    expect(out).not.toContain("Publication fingerprint");
    expect(out).not.toContain("Topology document");
    expect(out).toContain("No publication provenance");
  });

  it("still surfaces the bound version + a library deep-link", () => {
    expect(out).toContain("controlplane.security/v1alpha1");
    expect(out).toContain("/templates?template=tmpl-1&amp;version=ver-1");
  });
});
