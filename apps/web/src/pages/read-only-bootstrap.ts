// Pure, framework-free logic for the Proxmox Read-Only Discovery Bootstrap wizard (SECP-B7).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns. It handles
// ONLY non-secret values: an SSH PUBLIC key, a public host-key fingerprint, a bounded proof block.
// It NEVER accepts an SSH private key or a free-form command. Live deployment apply remains sealed.

import { ApiClientError } from "../api/client";
import type { BootstrapSession, BootstrapStatus } from "../api/types";

export const READ_ONLY_BOOTSTRAP_INTRO =
  "This wizard provisions a scoped, audit-only read-only access path on your Proxmox host. " +
  "You paste the worker's SSH PUBLIC key (never a private key), run one generated script on the " +
  "host, and the app automates the rest (endpoint binding, live-read authorization, binding " +
  "descriptor). Discovery is strictly read-only; the WORKER runs the probes, never the API.";

export const WORKER_NOT_API_NOTICE =
  "The API never connects to Proxmox and never runs a probe — a separate worker process performs " +
  "the read-only SSH probes using worker-mounted key material. The API only produces secret-free " +
  "desired state.";

/** The wizard steps, in order. */
export type BootstrapStep =
  | "create"
  | "run-script"
  | "complete"
  | "bind"
  | "run-discovery"
  | "done";

export const STEP_LABELS: Record<BootstrapStep, string> = {
  create: "1. Provide the worker's public key",
  "run-script": "2. Run the generated bootstrap script on Proxmox",
  complete: "3. Confirm bootstrap (host key fingerprint + proof)",
  bind: "4. Create the live-read authorization",
  "run-discovery": "5. Run read-only discovery",
  done: "Bound — ready for read-only discovery",
};

/** Derive the current wizard step from a session (or null before one exists). */
export function currentStep(session: BootstrapSession | null): BootstrapStep {
  if (!session) return "create";
  switch (session.status as BootstrapStatus) {
    case "pending":
      return "run-script";
    case "completed":
      return "bind";
    case "bound":
      return "run-discovery";
    default:
      return "create";
  }
}

/** A human, ordered checklist of what the generated bootstrap script will do (shown before running). */
export const SCRIPT_ACTIONS: string[] = [
  "Create/update a non-privileged system user 'secpdisc' with NO interactive shell (nologin).",
  "Create/update a minimal audit-only Proxmox role (Sys.Audit, VM.Audit, Datastore.Audit) and the 'secpdisc@pam' user, granting ONLY that read-only role.",
  "Install a root-owned forced-command wrapper that permits ONLY the closed read-only discovery command set and denies every write verb, shell, and injection.",
  "Add your worker's PUBLIC key to authorized_keys pinned to command=<wrapper>,no-pty,no-*-forwarding.",
  "Run a local self-test and print a bounded, secret-free proof block. It NEVER prints a private key.",
];

const PRIVATE_KEY_MARKER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i;
const SSH_PUBKEY = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/]{20,}={0,3}(\s+\S.*)?$/;

export interface FieldValidation {
  ok: boolean;
  message?: string;
}

/** Client-side pre-check for the worker PUBLIC key. Rejects private keys before they leave the UI. */
export function validatePublicKey(value: string): FieldValidation {
  const v = (value || "").trim();
  if (!v) return { ok: false, message: "Paste the worker's SSH public key." };
  if (PRIVATE_KEY_MARKER.test(v))
    return {
      ok: false,
      message: "That looks like a PRIVATE key. Paste only the PUBLIC key (ssh-ed25519 AAAA... ).",
    };
  if (v.includes("\n"))
    return { ok: false, message: "The public key must be a single line." };
  if (!SSH_PUBKEY.test(v))
    return { ok: false, message: "Expected an OpenSSH public key (e.g. 'ssh-ed25519 AAAA... ')." };
  return { ok: true };
}

/** Client-side pre-check for the public host-key fingerprint. */
export function validateFingerprint(value: string): FieldValidation {
  const v = (value || "").trim();
  if (!v.startsWith("SHA256:") || v.length <= 9)
    return { ok: false, message: "Expected an SSH 'SHA256:...' host-key fingerprint." };
  return { ok: true };
}

/**
 * Map any thrown error into a SAFE, human-readable message + code for display — never a generic
 * "Failed to fetch" and never a raw stack. A network failure and a backend error are distinguished.
 */
export function describeApiError(err: unknown): { code: string; message: string } {
  if (err instanceof ApiClientError) {
    if (err.code === "api_unreachable") return { code: err.code, message: err.message };
    const detail = err.details && err.details.length ? ` (${err.details.join("; ")})` : "";
    return { code: err.code, message: `${err.message}${detail}` };
  }
  if (err instanceof Error && /failed to fetch|networkerror|load failed/i.test(err.message)) {
    return {
      code: "api_unreachable",
      message: "Cannot reach the API. Check that the backend is running and reachable.",
    };
  }
  return { code: "error", message: err instanceof Error ? err.message : "Unexpected error." };
}

// SECP-B8: friendly, actionable labels for each discovery-readiness prerequisite check — so a
// missing prerequisite reads as a clear next step instead of an opaque `probe_source_sealed`.
export const PREREQUISITE_LABELS: Record<string, string> = {
  onboarding_active: "The target has an active onboarding.",
  substrate_eligible: "The target is marked staging-substrate eligible (grant it below).",
  bootstrap_session_present: "A read-only bootstrap session exists for this target.",
  bootstrap_completed: "The Proxmox bootstrap script was run and confirmed.",
  host_public_key_captured:
    "The host's SSH public key was captured at confirmation (re-confirm with the full proof block).",
  live_read_authorized: "A live-read authorization was created for this endpoint.",
  bootstrap_bound: "The bootstrap session is bound to the approved live-read authorization.",
};

/** Human label for a readiness prerequisite check name (falls back to the raw name). */
export function prerequisiteLabel(name: string): string {
  return PREREQUISITE_LABELS[name] ?? name;
}

// SECP-B8: worker-side prerequisites the CONTROL PLANE cannot observe (they live on the worker /
// deployment). Surfaced as guidance so a sealed worker never fails mysteriously with
// `probe_source_sealed` — the operator knows exactly which worker-side step is missing.
export const WORKER_SIDE_PREREQUISITES: string[] = [
  "The worker-managed discovery profile is enabled (SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true) so the worker generates its keys and assembles the bundle.",
  "The controlled-integration profile is enabled (SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true) on the worker.",
  "The worker's control-plane admission material (HTTPS endpoint + CA bundle) is provisioned, or the worker stays sealed and reads no SSH key.",
  "The worker has assembled its mounted bundle (it does this automatically once this target is bound and the host key is captured).",
];

/** Short status pill label. */
export function bootstrapStatusLabel(status: BootstrapStatus): string {
  const map: Record<BootstrapStatus, string> = {
    pending: "Awaiting bootstrap run",
    completed: "Bootstrap confirmed",
    bound: "Authorized — ready",
    refused: "Refused",
  };
  return map[status] ?? status;
}
