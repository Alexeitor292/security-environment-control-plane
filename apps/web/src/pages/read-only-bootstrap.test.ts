import { describe, expect, it } from "vitest";

import { ApiClientError } from "../api/client";
import type { BootstrapSession } from "../api/types";
import {
  bootstrapStatusLabel,
  currentStep,
  describeApiError,
  validateFingerprint,
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

describe("wizard step derivation", () => {
  it("starts at create before a session exists", () => {
    expect(currentStep(null)).toBe("create");
  });
  it("advances with session status", () => {
    expect(currentStep(session("pending"))).toBe("run-script");
    expect(currentStep(session("completed"))).toBe("bind");
    expect(currentStep(session("bound"))).toBe("run-discovery");
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
