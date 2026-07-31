/**
 * DEV-ONLY accessibility harness for the worker-enrollment surface.
 *
 * WHY IT EXISTS. The vitest suite runs in the `node` environment against
 * `renderToStaticMarkup`, so it can only assert MARKUP. Focus order, focus visibility, keyboard
 * operation, the accessibility tree a browser actually computes, and rendered contrast are all
 * invisible to it. Those are exactly the claims most likely to be wrong, so they are verified in a
 * real browser — and this file is what makes that verification repeatable instead of a one-off.
 *
 * WHY NOT THE REAL ROUTE. `/worker-enrollment` sits inside `AuthBoundary`, which needs
 * `/api/v1/auth/config` and `/api/v1/me`. Reaching it would require a running control plane. This
 * harness mounts `WorkerEnrollmentView` — the same presentational component the route renders —
 * directly, with fixture props and local state. No router, no auth, no network.
 *
 * WHAT IT IS NOT. It is not a second implementation and it must never become one. It renders the
 * shipped component and owns nothing but React state; the handlers below move that state and do
 * not model any controller behaviour. `onRefreshTracked` in particular only exercises the busy
 * affordance — it fetches nothing and changes no row, because simulating a controller response
 * here would let this file "verify" something the product does not do.
 *
 * It is excluded from the production bundle: `vite build` takes `index.html` as its only input, so
 * neither this module nor `a11y-harness.html` is reachable from the shipped app.
 */

import { useState } from "react";
import ReactDOM from "react-dom/client";
import { MemoryRouter } from "react-router-dom";

import type { EnrollmentInvitation, EnrollmentStatus, Principal } from "../api/types";
import { Sidebar } from "../components/shell/Sidebar";
import {
  WorkerEnrollmentView,
  type WorkerEnrollmentViewProps,
} from "../pages/WorkerEnrollment";
import {
  INVITATION_CLEARED_NOTICE,
  trackedFromInvitation,
  type TrackedEnrollment,
  type TrackedFilter,
} from "../pages/worker-enrollment";

import "../components/shell/shell.css";
import "../design/tokens.css";
import "../styles.css";

/**
 * The nav entry is permission-gated, so a keyboard pass has to see BOTH outcomes. `?nav=denied`
 * renders the sidebar for a principal holding neither enrollment permission; the default renders
 * it for one holding manage only — the case that would have been wrongly hidden had the entry been
 * gated on `enrollment:read` alone.
 */
const DENIED = new URLSearchParams(window.location.search).get("nav") === "denied";

const PRINCIPAL: Principal = {
  user_id: "u-1",
  organization_id: "org-1",
  email: "operator@example.test",
  permissions: DENIED ? ["exercise:read"] : ["enrollment:manage"],
  is_dev_fallback: false,
};

const ID = "sha256:" + "a".repeat(64);

const INVITATION: EnrollmentInvitation = {
  enrollment_id: ID,
  invitation_id: "sha256:" + "b".repeat(64),
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_id: "sha256:" + "c".repeat(64),
  controller_trust_anchor_hex: "d".repeat(64),
  controller_origin: "https://controller.example",
  release_digest: "sha256:" + "e".repeat(64),
  transaction_id: "txn-0123456789abcdef",
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

const NOW = Date.parse("2026-07-30T10:00:00+00:00");

const SEED: TrackedEnrollment[] = [
  trackedFromInvitation(INVITATION),
  {
    enrollmentId: "sha256:" + "9".repeat(64),
    siteLabel: "",
    createdAt: "",
    expiresAt: "2026-07-30T09:00:00+00:00",
    state: "offer_transported",
    revision: 3,
  },
  {
    enrollmentId: "sha256:" + "8".repeat(64),
    siteLabel: "site-two",
    createdAt: "2026-07-30T09:00:00+00:00",
    expiresAt: "2026-07-30T11:00:00+00:00",
    state: "healthy",
    revision: 7,
  },
];

function Harness() {
  const [siteLabel, setSiteLabel] = useState("site-one");
  const [ttlSeconds, setTtlSeconds] = useState("3600");
  const [invitation, setInvitation] = useState<EnrollmentInvitation | null>(INVITATION);
  const [revealed, setRevealed] = useState(false);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const [dismissNotice, setDismissNotice] = useState<string | null>(null);
  const [lookupId, setLookupId] = useState("");
  const [status] = useState<EnrollmentStatus | null>(STATUS);
  const [tracked, setTracked] = useState<readonly TrackedEnrollment[]>(SEED);
  const [trackedFilter, setTrackedFilter] = useState<TrackedFilter>("all");
  const [refreshingId, setRefreshingId] = useState<string | null>(null);

  const props: WorkerEnrollmentViewProps = {
    permissions: { read: true, manage: true },
    siteLabel,
    onSiteLabelChange: setSiteLabel,
    ttlSeconds,
    onTtlSecondsChange: setTtlSeconds,
    onCreate: () => {},
    creating: false,
    createError: null,
    invitation,
    revealed,
    onToggleReveal: () => setRevealed((open) => !open),
    onCopyHandoff: () =>
      setCopyNotice("Copied. Deliver it to one worker, then clear your clipboard."),
    copyNotice,
    onDismissInvitation: () => {
      setInvitation(null);
      setRevealed(false);
      setCopyNotice(null);
      setDismissNotice(INVITATION_CLEARED_NOTICE);
    },
    dismissNotice,
    lookupId,
    onLookupIdChange: setLookupId,
    onLookup: () => {},
    lookingUp: false,
    status,
    statusError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    tracked,
    trackedFilter,
    onTrackedFilterChange: setTrackedFilter,
    // Busy affordance only. It deliberately fetches nothing and changes no row: this harness
    // must not be able to "verify" a data flow the product does not perform.
    onRefreshTracked: (enrollmentId) => {
      setRefreshingId(enrollmentId);
      window.setTimeout(() => setRefreshingId(null), 800);
    },
    onForgetTracked: (enrollmentId) =>
      setTracked((list) => list.filter((e) => e.enrollmentId !== enrollmentId)),
    refreshingId,
    nowMs: NOW,
  };

  return (
    <MemoryRouter>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "16px" }}>
        <div className="shell-sidebar" style={{ flex: "none" }}>
          <Sidebar principal={PRINCIPAL} collapsed={false} />
        </div>
        <div className="app-shell__main" style={{ flex: 1, minWidth: 0, padding: "24px" }}>
          <WorkerEnrollmentView {...props} />
        </div>
      </div>
    </MemoryRouter>
  );
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(<Harness />);
