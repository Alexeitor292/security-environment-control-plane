import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import type { TopologyDocumentDetail, TopologyRevisionDetail } from "../api/types";
import { EnvironmentPublication } from "./EnvironmentPublication";
import { TopologyPersistencePanel } from "./TopologyPersistencePanel";
import type { ValidationView } from "./topology-persistence";

// Static-render (server) tests — the repo's node-env convention (no jsdom). They assert rendered
// structure/accessibility, complementing the pure-logic tests in environment-publication.test.ts.

function rev(over: Partial<TopologyRevisionDetail> = {}): TopologyRevisionDetail {
  return {
    id: "rev-1",
    document_id: "doc-1",
    revision_number: 1,
    parent_revision_id: null,
    schema_version: "secp.topology/v1",
    content_hash: "sha256:" + "a".repeat(64),
    status: "approved",
    change_note: null,
    source_environment_version_id: null,
    created_by: null,
    created_at: "2026-01-01T00:00:00",
    decided_by: null,
    decided_at: null,
    document_content: { schema_version: "secp.topology/v1", nodes: [], edges: [], networks: [], zones: [] },
    ...over,
  };
}

function doc(): TopologyDocumentDetail {
  const current = rev();
  return {
    id: "doc-1",
    organization_id: "org-1",
    display_name: "Doc",
    status: "approved",
    source_environment_version_id: null,
    exercise_id: null,
    current_revision_id: current.id,
    validated_revision_id: null,
    submitted_revision_id: null,
    approved_revision_id: current.id,
    revision_count: 1,
    created_at: "2026-01-01T00:00:00",
    updated_at: "2026-01-01T00:00:00",
    current_revision: current,
    current_validation_status: "valid",
  };
}

const validationView: ValidationView = {
  display: "valid",
  label: "Valid",
  errorCount: 0,
  warningCount: 0,
  findings: [],
};

function panelHtml(over: Record<string, unknown>): string {
  const props = {
    posture: "approved" as const,
    document: doc(),
    revisions: [],
    validation: validationView,
    validationResult: null,
    baseRevisionNumber: 1,
    baseHash: "sha256:" + "a".repeat(64),
    actions: {
      save: { eligible: false, reason: "locked" },
      validate: { eligible: false, reason: "locked" },
      submit: { eligible: false, reason: "locked" },
      approve: { eligible: false, reason: "locked" },
      reject: { eligible: false, reason: "locked" },
    },
    busy: false,
    error: null,
    onSave: () => {},
    onValidate: () => {},
    onSubmit: () => {},
    onApprove: () => {},
    onReject: () => {},
    onReload: () => {},
    onLoadRevision: () => {},
    onDiscardAndLoadLatest: () => {},
    viewingRevisionId: "rev-1",
    ...over,
  };
  return renderToStaticMarkup(createElement(TopologyPersistencePanel, props));
}

describe("contextual publish entry point (topology panel)", () => {
  it("offers a Publish version action when eligible", () => {
    const html = panelHtml({ publish: { eligible: true }, onPublish: () => {} });
    expect(html).toContain("Publish version");
    expect(html).toContain("Publish environment version");
    // no "why unavailable" reasons list for the publish card when eligible
    expect(html).not.toContain("Why publishing is unavailable");
  });

  it("shows the accessible reason and a disabled control when ineligible", () => {
    const html = panelHtml({
      publish: { eligible: false, reason: "Requires the version:publish permission." },
      onPublish: () => {},
    });
    expect(html).toContain("Why publishing is unavailable");
    expect(html).toContain("Requires the version:publish permission.");
    expect(html).toContain("disabled");
  });

  it("renders no publish card when the entry point is not provided (backward compatible)", () => {
    const html = panelHtml({});
    expect(html).not.toContain("Publish environment version");
  });
});

describe("publication page smoke render", () => {
  it("mounts under its route (document id only) and shows the workflow scaffold without mutating", () => {
    // renderToStaticMarkup runs no effects, so no data is loaded and no API call fires — proving
    // there is no mutation (or fetch) on initial render. The page shows its heading + step rail.
    const html = renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: ["/environment-publication/doc-1"] },
        createElement(
          Routes,
          null,
          createElement(Route, {
            path: "/environment-publication/:documentId",
            element: createElement(EnvironmentPublication),
          }),
        ),
      ),
    );
    expect(html).toContain("Publish environment version");
    expect(html).toContain("Approved topology"); // step rail label
    expect(html).not.toContain("Publishing…"); // never mid-publish on first render
  });
});
