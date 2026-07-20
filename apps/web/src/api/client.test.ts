import { afterEach, describe, expect, it, vi } from "vitest";

import type { EnvironmentPublicationRequest, Version } from "./types";
import { api, buildUrl } from "./client";

describe("buildUrl", () => {
  it("joins a path onto the API base", () => {
    const url = buildUrl("/api/v1/templates");
    expect(url).toContain("/api/v1/templates");
  });

  it("appends query params", () => {
    const url = buildUrl("/api/v1/audit", { exercise_id: "abc" });
    expect(url).toContain("exercise_id=abc");
  });
});

const VERSION: Version = {
  id: "v1",
  template_id: "t1",
  version_number: 1,
  api_version: "controlplane.security/v1alpha2",
  content_hash: "sha256:" + "a".repeat(64),
  spec: { apiVersion: "controlplane.security/v1alpha2" },
  created_at: "2026-01-01T00:00:00",
  publication_provenance: {
    topology_document_id: "d",
    topology_revision_id: "r",
    topology_content_hash: "sha256:" + "b".repeat(64),
    topology_validation_result_id: "vr",
    topology_validation_result_hash: "sha256:" + "c".repeat(64),
    base_environment_version_id: null,
    publication_contract_version: "secp.publication/v1",
    publication_fingerprint: "sha256:" + "f".repeat(64),
  },
};

const REQ: EnvironmentPublicationRequest = {
  template_id: "t1",
  definition: { apiVersion: "controlplane.security/v1alpha2", kind: "Environment" },
  topology_document_id: "d",
  topology_revision_id: "r",
  expected_topology_content_hash: "sha256:" + "e".repeat(64),
  validation_result_id: "vr",
  base_environment_version_id: null,
};

function mockFetch(status: number, body?: unknown) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    text: async () => (body === undefined ? "" : JSON.stringify(body)),
  }));
}

describe("api.getEnvironmentVersion", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads exactly one version by id via GET (no template id, no query scan)", async () => {
    const f = mockFetch(200, VERSION);
    vi.stubGlobal("fetch", f);
    const v = await api.getEnvironmentVersion("v1");
    expect(v).toEqual(VERSION);
    const [url, init] = f.mock.calls[0] as unknown as [string, { method?: string }];
    expect(url).toContain("/api/v1/environment-versions/v1");
    expect(init?.method).toBe("GET");
  });

  it("propagates a not_found as a closed client error (no latest/nearest fallback)", async () => {
    vi.stubGlobal("fetch", mockFetch(404, { error: { code: "not_found" } }));
    await expect(api.getEnvironmentVersion("missing")).rejects.toMatchObject({
      code: "not_found",
      status: 404,
    });
  });
});

describe("api.publishEnvironmentVersion", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("maps HTTP 201 to created=true and preserves the version body", async () => {
    vi.stubGlobal("fetch", mockFetch(201, VERSION));
    const r = await api.publishEnvironmentVersion(REQ);
    expect(r.created).toBe(true);
    expect(r.status).toBe(201);
    expect(r.version).toEqual(VERSION);
  });

  it("maps HTTP 200 to created=false (idempotent replay)", async () => {
    vi.stubGlobal("fetch", mockFetch(200, VERSION));
    const r = await api.publishEnvironmentVersion(REQ);
    expect(r.created).toBe(false);
    expect(r.status).toBe(200);
    expect(r.version.id).toBe("v1");
  });

  it("fails closed on any other successful status", async () => {
    vi.stubGlobal("fetch", mockFetch(202, VERSION));
    await expect(api.publishEnvironmentVersion(REQ)).rejects.toMatchObject({
      code: "environment_publication_unexpected_status",
    });
  });

  it("keeps closed server errors closed (code + status)", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(403, { error: { code: "version_publish_permission_denied" } }),
    );
    await expect(api.publishEnvironmentVersion(REQ)).rejects.toMatchObject({
      code: "version_publish_permission_denied",
      status: 403,
    });
  });

  it("surfaces a network failure as api_unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    await expect(api.publishEnvironmentVersion(REQ)).rejects.toMatchObject({ code: "api_unreachable" });
  });

  it("sends only the seven allowlisted fields — no idempotency key or fingerprint", async () => {
    const f = mockFetch(201, VERSION);
    vi.stubGlobal("fetch", f);
    await api.publishEnvironmentVersion(REQ);
    // fetch(url, init) — read the init's serialized body (mock impl takes no typed params).
    const init = (f.mock.calls[0] as unknown as [string, { body?: string }])[1];
    const sent = JSON.parse(init?.body ?? "{}");
    expect(Object.keys(sent).sort()).toEqual(
      [
        "base_environment_version_id",
        "definition",
        "expected_topology_content_hash",
        "template_id",
        "topology_document_id",
        "topology_revision_id",
        "validation_result_id",
      ].sort(),
    );
    expect(sent).not.toHaveProperty("idempotency_key");
    expect(sent).not.toHaveProperty("publication_fingerprint");
  });
});

describe("api.reviewAndLinkWorkerNode", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses only the narrow worker-node subroute and reviewed non-secret fields", async () => {
    const f = mockFetch(200, {});
    vi.stubGlobal("fetch", f);
    const body = {
      expected_node_revision: 3,
      expected_ssh_public_key_fingerprint: "SHA256:worker",
      expected_admission_anchor_fingerprint: "sha256:" + "a".repeat(64),
      deployment_binding: "production-worker",
      proof_id: "change-review-1234",
      issuer: "platform-operator",
      deployment_binding_review_confirmed: true,
      verification_anchor_review_confirmed: true,
      rotation_revocation_review_confirmed: true,
    } as const;

    await api.reviewAndLinkWorkerNode("node-1", body);

    const [url, init] = f.mock.calls[0] as unknown as [
      string,
      { method?: string; body?: string },
    ];
    expect(url).toContain(
      "/read-only-bootstrap/worker-nodes/node-1/identity-approval-link",
    );
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body ?? "{}")).toEqual(body);
  });
});
