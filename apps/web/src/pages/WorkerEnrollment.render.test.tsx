import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { WorkerEnrollmentView, type WorkerEnrollmentViewProps } from "./WorkerEnrollment";

const ID = "sha256:" + "a".repeat(64);
const INVITATION_ID = "sha256:" + "b".repeat(64);
const TRANSACTION_ID = "txn-0123456789abcdef";
const NOW = Date.parse("2026-07-30T10:00:00+00:00");

const INVITATION: EnrollmentInvitation = {
  enrollment_id: ID,
  invitation_id: INVITATION_ID,
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_id: "sha256:" + "c".repeat(64),
  controller_trust_anchor_hex: "d".repeat(64),
  controller_origin: "https://controller.example",
  release_digest: "sha256:" + "e".repeat(64),
  transaction_id: TRANSACTION_ID,
  deployment_site_label: "site-one",
  created_at: "2026-07-30T10:00:00+00:00",
  expires_at: "2026-07-30T11:00:00+00:00",
  state: "invited",
  revision: 0,
};

const STATUS: EnrollmentStatus = {
  enrollment_id: ID,
  state: "worker_bound",
  revision: 1,
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_fingerprint: "cccccccccccc",
  worker_installation_id: "worker-one",
  worker_key_fingerprint: "ffffffffffff",
  release_fingerprint: "eeeeeeeeeeee",
  offer_fingerprint: "",
  result_fingerprint: "",
  expires_at: "2026-07-30T11:00:00+00:00",
  updated_at: "2026-07-30T10:05:00+00:00",
  refusal_reason: "",
};

function html(over: Partial<WorkerEnrollmentViewProps> = {}): string {
  const props: WorkerEnrollmentViewProps = {
    permissions: { read: true, manage: true },
    siteLabel: "site-one",
    onSiteLabelChange: () => {},
    ttlSeconds: "3600",
    onTtlSecondsChange: () => {},
    onCreate: () => {},
    creating: false,
    createError: null,
    invitation: null,
    revealed: false,
    onReveal: () => {},
    onCopyHandoff: () => {},
    copyNotice: null,
    onDismissInvitation: () => {},
    lookupId: "",
    onLookupIdChange: () => {},
    onLookup: () => {},
    lookingUp: false,
    status: null,
    statusError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    recent: [],
    nowMs: NOW,
    ...over,
  };
  return renderToStaticMarkup(createElement(WorkerEnrollmentView, props));
}

describe("WorkerEnrollmentView — hand-off material exposure", () => {
  // The single most important behaviour on this page: the invitation is bearer-grade, so it must
  // not be in the document until the operator explicitly asks for it.
  it("renders no invitation material before the operator reveals it", () => {
    const out = html({ invitation: INVITATION, revealed: false });
    for (const secretish of [
      INVITATION_ID,
      TRANSACTION_ID,
      INVITATION.controller_key_id,
      INVITATION.release_digest,
      INVITATION.controller_origin,
      INVITATION.controller_trust_anchor_hex,
    ]) {
      expect(out, secretish).not.toContain(secretish);
    }
  });

  it("still offers the reveal control and states why it matters", () => {
    const out = html({ invitation: INVITATION, revealed: false });
    expect(out).toContain("Reveal invitation for hand-off");
    expect(out).toContain("Treat this invitation as a credential");
    expect(out).toContain("only time these values are available");
  });

  it("renders every hand-off field once revealed", () => {
    const out = html({ invitation: INVITATION, revealed: true });
    for (const field of [
      ID,
      INVITATION_ID,
      INVITATION.controller_installation_id,
      INVITATION.controller_key_id,
      INVITATION.controller_origin,
      TRANSACTION_ID,
      INVITATION.release_digest,
      INVITATION.expires_at,
    ]) {
      expect(out, field).toContain(field);
    }
  });

  it("shows the expiry alongside the material", () => {
    expect(html({ invitation: INVITATION, revealed: true })).toContain("Expires in 1 hour");
  });

  it("renders nothing at all when there is no invitation", () => {
    const out = html({ invitation: null });
    expect(out).not.toContain("Hand this to the worker");
    expect(out).not.toContain(INVITATION_ID);
  });
});

describe("WorkerEnrollmentView — no fabricated lifecycle authority", () => {
  // The lifecycle has no approval edge. A button implying one would be fiction.
  it("offers no approve or reject affordance in any state", () => {
    for (const state of [
      "invited",
      "worker_bound",
      "offer_transported",
      "result_transported",
      "verified",
      "healthy",
    ]) {
      const out = html({ status: { ...STATUS, state } }).toLowerCase();
      expect(out, state).not.toContain(">approve");
      expect(out, state).not.toContain(">reject");
      expect(out, state).not.toContain("approve enrollment");
      expect(out, state).not.toContain("reject enrollment");
    }
  });

  it("says plainly that only the worker advances an enrollment", () => {
    expect(html()).toContain("Enrollment advances only on evidence the worker signs");
  });

  it("discloses that there is no inventory or queue", () => {
    expect(html()).toContain("no enrollment inventory or pending queue");
  });

  it("labels the recent list as tab-local, not a server inventory", () => {
    expect(html()).toContain("kept only until you reload");
    expect(html()).toContain("This is not an inventory");
  });
});

describe("WorkerEnrollmentView — permission gating explains itself", () => {
  it("names the missing permission next to a disabled create", () => {
    const out = html({ permissions: { read: true, manage: false } });
    expect(out).toContain("Requires the enrollment:manage permission.");
    expect(out).toContain("disabled");
  });

  it("names the missing permission next to a disabled look-up", () => {
    const out = html({ permissions: { read: false, manage: true } });
    expect(out).toContain("Requires the enrollment:read permission.");
  });

  // The backend pins that manage does not imply read; the page says so before it bites.
  it("warns a manage-only principal that status will be refused", () => {
    const out = html({ permissions: { read: false, manage: true } });
    expect(out).toContain("manage does not include read");
  });

  it("does not warn when the principal holds both", () => {
    expect(html({ permissions: { read: true, manage: true } })).not.toContain(
      "manage does not include read",
    );
  });
});

describe("WorkerEnrollmentView — status", () => {
  it("renders the lifecycle state as a badge and the bounded projection rows", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("worker bound"); // statusDisplayLabel replaces underscores
    expect(out).toContain("cccccccccccc");
    expect(out).toContain("worker-one");
  });

  it("names an unestablished fingerprint rather than leaving it blank", () => {
    expect(html({ status: STATUS })).toContain("Not established yet");
  });

  it("offers revoke on a live enrollment and explains that it is permanent", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("Revoke enrollment");
    expect(out).toContain("cannot be undone");
  });

  it("disables revoke on a terminal enrollment and says which terminal", () => {
    const out = html({ status: { ...STATUS, state: "refused" } });
    expect(out).toContain("already refused");
    expect(out).toContain("disabled");
  });

  it("renders no status card until an enrollment was looked up", () => {
    expect(html({ status: null })).not.toContain("Enrollment status");
  });
});

describe("WorkerEnrollmentView — errors are closed-code copy", () => {
  it("renders mapped copy plus the code, never a backend message", () => {
    const out = html({
      createError: { code: "enrollment_controller_identity_unavailable", text: "" },
    });
    expect(out).toContain("no active enrollment identity yet");
    expect(out).toContain("enrollment_controller_identity_unavailable");
  });

  it("frames the uncommissioned-controller refusal as expected, not as a failure", () => {
    const out = html({
      createError: { code: "enrollment_controller_identity_unavailable", text: "" },
    });
    expect(out).toContain("nothing is broken");
  });

  it("distinguishes a missing permission from a cross-organization refusal", () => {
    expect(html({ statusError: { code: "forbidden", text: "" } })).toContain(
      "separate permissions",
    );
    expect(html({ statusError: { code: "enrollment_forbidden", text: "" } })).toContain(
      "another organization",
    );
  });
});

describe("WorkerEnrollmentView — busy states", () => {
  it("disables and relabels the in-flight action", () => {
    expect(html({ creating: true })).toContain("Creating…");
    expect(html({ lookingUp: true })).toContain("Loading…");
    expect(html({ status: STATUS, revoking: true })).toContain("Revoking…");
  });
});
