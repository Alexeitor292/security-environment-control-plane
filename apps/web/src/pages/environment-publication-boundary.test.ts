import { describe, expect, it } from "vitest";

import CLIENT from "../api/client.ts?raw";
import TYPES from "../api/types.ts?raw";
import NAV from "../components/shell/nav.ts?raw";
import MAIN from "../main.tsx?raw";
import PAGE from "./EnvironmentPublication.tsx?raw";
import MODULE from "./environment-publication.ts?raw";

// Static architecture/security boundary tests for the publication workflow UI (ADR-016 PR D).
// The frontend surface must stay control-plane-read + publish only: it never imports
// worker/provider/transport/infra code, never triggers a downstream mutation, never auto-publishes,
// never sends a caller idempotency key / publication fingerprint, and the contextual route carries
// only the document id. (That no backend/migration file changed is enforced by git status.)

const FORBIDDEN_IMPORT = /from\s+["'][^"']*(worker|provider|transport|opentofu|terraform|socket|subprocess|secret-resolver)[^"']*["']/i;

describe("publication page import boundary", () => {
  it("imports no worker/provider/transport/infra module", () => {
    expect(FORBIDDEN_IMPORT.test(PAGE)).toBe(false);
    expect(FORBIDDEN_IMPORT.test(MODULE)).toBe(false);
  });

  it("calls only publication + read APIs — never a downstream mutation", () => {
    const forbiddenCalls = [
      "createExercise",
      "generatePlan",
      "submitPlan",
      "approvePlan",
      "deployExercise",
      "destroyExercise",
      "createStagingDeployment",
      "deployStagingDeployment",
      "requestTargetDiscovery",
      "dispatch",
    ];
    for (const call of forbiddenCalls) {
      expect(PAGE.includes(`api.${call}`)).toBe(false);
    }
    // the ONLY publish call is the publication endpoint
    expect(PAGE).toContain("api.publishEnvironmentVersion");
  });

  it("does not auto-publish from an effect (publish only from an explicit handler)", () => {
    // no useEffect body may contain the publish call — split on useEffect( and scan each block.
    const effects = PAGE.split("useEffect(").slice(1);
    for (const body of effects) {
      const block = body.slice(0, body.indexOf("}, ["));
      expect(block.includes("publishEnvironmentVersion")).toBe(false);
    }
    // publish is invoked from an onClick handler
    expect(PAGE).toContain("onClick={runPublish}");
  });

  it("sends no caller idempotency key or publication fingerprint", () => {
    for (const src of [PAGE, MODULE, TYPES, CLIENT]) {
      expect(src.includes("idempotency_key")).toBe(false);
    }
    // the request type/builder never place publication_fingerprint INTO the request
    expect(MODULE).not.toMatch(/publication_fingerprint\s*:/); // no fingerprint field written into a request
  });
});

describe("route + navigation boundary", () => {
  it("the contextual route carries only the document id", () => {
    expect(MAIN).toContain("environment-publication/:documentId");
    for (const forbidden of [":revisionId", ":validationId", ":hash", ":versionId", ":baseVersionId"]) {
      expect(MAIN.includes(`environment-publication/${forbidden}`)).toBe(false);
    }
  });

  it("adds no global navigation item implying general publication-document discovery", () => {
    expect(/publish/i.test(NAV)).toBe(false);
    expect(NAV.includes("environment-publication")).toBe(false);
  });
});

describe("request-schema boundary", () => {
  it("EnvironmentPublicationRequest exposes exactly the seven allowlisted fields", () => {
    const block = TYPES.slice(
      TYPES.indexOf("export interface EnvironmentPublicationRequest"),
      TYPES.indexOf("export interface EnvironmentPublicationClientResult"),
    );
    for (const field of [
      "template_id",
      "definition",
      "topology_document_id",
      "topology_revision_id",
      "expected_topology_content_hash",
      "validation_result_id",
      "base_environment_version_id",
    ]) {
      expect(block).toContain(field);
    }
    for (const forbidden of ["idempotency_key", "publication_fingerprint", "spec.topology"]) {
      expect(block.includes(forbidden)).toBe(false);
    }
  });
});
