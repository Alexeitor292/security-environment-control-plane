import { describe, expect, it } from "vitest";

import { ApiClientError } from "../api/client";
import type { BootstrapSession, WorkerDiscoveryNode } from "../api/types";
import {
  PREREQUISITE_LABELS,
  WORKER_SIDE_PREREQUISITES,
  bootstrapStatusLabel,
  currentStep,
  describeApiError,
  matchWorkerNodeByPublicKeyFingerprint,
  prerequisiteLabel,
  validateFingerprint,
  validateNodeIdentityReview,
  validatePublicKey,
} from "./read-only-bootstrap";

const session = (status: BootstrapSession["status"]): BootstrapSession => ({
  id: "s1",
  execution_target_id: "t1",
  onboarding_id: "o1",
  account: "secpdisc",
  pve_role: "SECPDiscoveryReadOnly",
  worker_ssh_public_key_fingerprint: "SHA256:abc",
  status,
  ssh_port: 22,
  host_key_fingerprint: null,
  endpoint_binding_hash: null,
  live_read_authorization_id: null,
  authorization_version: null,
  failure_code: null,
  expires_at: "",
  created_at: "",
  updated_at: "",
});

const node = (id: string, fingerprint = "SHA256:worker-a"): WorkerDiscoveryNode => ({
  id,
  organization_id: "org-1",
  node_label: `worker-${id}`,
  ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij worker@secp",
  ssh_public_key_fingerprint: fingerprint,
  admission_anchor_hex: "a".repeat(64),
  admission_anchor_fingerprint: "sha256:" + "b".repeat(64),
  revision: 1,
  worker_identity_registration_id: null,
  created_at: "",
  updated_at: "",
});

describe("wizard step derivation", () => {
  it("starts at create before a session exists", () => {
    expect(currentStep(null)).toBe("create");
  });
  it("advances with session status", () => {
    expect(currentStep(session("pending"))).toBe("run-script");
    expect(currentStep(session("completed"))).toBe("bind");
    expect(currentStep(session("bound"))).toBe("run-discovery");
    expect(currentStep(session("refused"))).toBe("refused");
  });
});

describe("validatePublicKey", () => {
  it("rejects a private key", () => {
    const r = validatePublicKey("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----");
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/PRIVATE key/i);
  });
  it("rejects empty + malformed", () => {
    expect(validatePublicKey("").ok).toBe(false);
    expect(validatePublicKey("not a key").ok).toBe(false);
    expect(validatePublicKey("ssh-ed25519").ok).toBe(false);
  });
  it("accepts a well-formed public key", () => {
    expect(validatePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij worker@secp").ok).toBe(
      true,
    );
  });
});

describe("validateFingerprint", () => {
  it("requires SHA256:", () => {
    expect(validateFingerprint("MD5:aa").ok).toBe(false);
    expect(validateFingerprint("SHA256:" + "A".repeat(43)).ok).toBe(true);
  });
});

describe("explicit worker-node identity review", () => {
  const completeReview = {
    deploymentBinding: "production-worker",
    proofId: "change-review-1234",
    issuer: "platform-operator",
    deploymentBindingReviewed: true,
    verificationAnchorReviewed: true,
    rotationRevocationReviewed: true,
  };

  it("requires safe opaque metadata and all three explicit confirmations", () => {
    expect(validateNodeIdentityReview(completeReview).ok).toBe(true);
    expect(
      validateNodeIdentityReview({ ...completeReview, deploymentBinding: "vault:value" }).ok,
    ).toBe(false);
    expect(
      validateNodeIdentityReview({ ...completeReview, verificationAnchorReviewed: false }).ok,
    ).toBe(false);
    expect(
      validateNodeIdentityReview({ ...completeReview, rotationRevocationReviewed: false }).ok,
    ).toBe(false);
  });

  it("reload-matches one node by the session's public-key fingerprint", () => {
    const match = matchWorkerNodeByPublicKeyFingerprint(
      [node("old", "SHA256:old"), node("current", "SHA256:session")],
      "SHA256:session",
    );
    expect(match.ok).toBe(true);
    if (match.ok) expect(match.node.id).toBe("current");
  });

  it("fails closed on missing or ambiguous fingerprint matches", () => {
    expect(matchWorkerNodeByPublicKeyFingerprint([node("one")], "SHA256:missing")).toEqual({
      ok: false,
      reason: "missing",
    });
    expect(
      matchWorkerNodeByPublicKeyFingerprint(
        [node("one", "SHA256:same"), node("two", "SHA256:same")],
        "SHA256:same",
      ),
    ).toEqual({ ok: false, reason: "ambiguous" });
  });
});

describe("describeApiError — never a generic 'Failed to fetch'", () => {
  it("surfaces a backend error code + message", () => {
    const d = describeApiError(new ApiClientError(422, "invalid_bootstrap_input", "bad key"));
    expect(d.code).toBe("invalid_bootstrap_input");
    expect(d.message).toContain("bad key");
  });
  it("maps a raw network TypeError to a clear message", () => {
    const d = describeApiError(new TypeError("Failed to fetch"));
    expect(d.code).toBe("api_unreachable");
    expect(d.message).not.toMatch(/failed to fetch/i);
    expect(d.message).toMatch(/reach the API/i);
  });
  it("passes through the client's api_unreachable error", () => {
    const d = describeApiError(new ApiClientError(0, "api_unreachable", "Cannot reach the API at X."));
    expect(d.code).toBe("api_unreachable");
    expect(d.message).toMatch(/reach the API/i);
  });
  it("includes validation details when present", () => {
    const d = describeApiError(new ApiClientError(422, "e", "invalid", ["field a", "field b"]));
    expect(d.message).toContain("field a");
  });
});

describe("bootstrapStatusLabel", () => {
  it("labels each status", () => {
    expect(bootstrapStatusLabel("pending")).toMatch(/Awaiting/);
    expect(bootstrapStatusLabel("bound")).toMatch(/ready/i);
  });
});

describe("SECP-B8 readiness prerequisite labels", () => {
  it("gives a friendly, actionable label for each known check", () => {
    for (const name of Object.keys(PREREQUISITE_LABELS)) {
      expect(prerequisiteLabel(name).length).toBeGreaterThan(0);
      expect(prerequisiteLabel(name)).not.toBe(name);
    }
  });
  it("falls back to the raw name for an unknown check", () => {
    expect(prerequisiteLabel("some_new_check")).toBe("some_new_check");
  });
  it("surfaces worker-side prerequisites so a sealed worker is never a mystery", () => {
    expect(WORKER_SIDE_PREREQUISITES.length).toBeGreaterThan(0);
    // The guidance must name the worker-managed profile flag operators must set.
    expect(WORKER_SIDE_PREREQUISITES.join(" ")).toMatch(/SECP_DISCOVERY_WORKER_MANAGED_BUNDLE/);
  });
});
