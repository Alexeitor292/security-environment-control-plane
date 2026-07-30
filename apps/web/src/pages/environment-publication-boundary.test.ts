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
    // The publication-owned files carry no idempotency key at all.
    for (const src of [PAGE, MODULE]) {
      expect(src.includes("idempotency_key")).toBe(false);
    }
    // types.ts and client.ts are SHARED with every other feature, and an unrelated surface may
    // legitimately own an idempotency key (the supported worker-enrollment create is retry-safe by
    // contract and requires one). So assert the property that actually matters here — that the
    // PUBLICATION request type and the PUBLICATION client method carry none — rather than scanning
    // whole shared files, which only ever passed because no other feature had one.
    //
    // Every anchor below is proven present BEFORE it is used to slice, and every slice is proven
    // to contain known content BEFORE a negative assertion is made about it. A narrowed check that
    // can no longer find its target must fail loudly — it must never slice nothing and pass
    // vacuously, which would leave this test green while testing nothing at all.

    // --- the publication REQUEST TYPE ---------------------------------------------------------
    const typeStart = TYPES.indexOf("export interface EnvironmentPublicationRequest");
    expect(
      typeStart,
      "EnvironmentPublicationRequest was renamed or removed from api/types.ts — re-anchor this test",
    ).toBeGreaterThan(-1);
    // A top-level interface ends at the first closing brace in column 0, so a nested object type
    // inside the interface cannot truncate this slice early.
    const typeEnd = TYPES.indexOf("\n}", typeStart);
    expect(
      typeEnd,
      "EnvironmentPublicationRequest has no column-0 closing brace — re-anchor this test",
    ).toBeGreaterThan(typeStart);
    const requestType = TYPES.slice(typeStart, typeEnd);
    // Prove the slice really is the interface body before trusting a negative assertion about it.
    expect(requestType).toContain("topology_document_id");
    expect(requestType).toContain("expected_topology_content_hash");
    expect(requestType).not.toContain("idempotency_key");

    // --- the publication CLIENT METHOD --------------------------------------------------------
    const methodStart = CLIENT.indexOf("publishEnvironmentVersion:");
    expect(
      methodStart,
      "publishEnvironmentVersion was renamed or removed from api/client.ts — re-anchor this test",
    ).toBeGreaterThan(-1);
    const tail = CLIENT.slice(methodStart);
    // Bounded on the method's OWN closing "  }," at two-space indent, never on the identity of
    // whichever method happens to follow it — so inserting, removing or reordering a neighbouring
    // client method cannot silently change what this window covers.
    const methodEnd = tail.search(/^ {2}\},$/m);
    expect(
      methodEnd,
      "publishEnvironmentVersion no longer ends with a two-space-indented '},' — re-anchor this test",
    ).toBeGreaterThan(-1);
    const publishMethod = tail.slice(0, methodEnd);
    // Prove the slice really is the publish method before trusting a negative assertion about it.
    expect(publishMethod).toContain("/api/v1/environment-versions/publish");
    expect(publishMethod).not.toContain("idempotency_key");
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
