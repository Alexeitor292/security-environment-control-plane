/**
 * DEV-ONLY accessibility harness for the enrollment surfaces.
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
 *
 * QUERY SWITCHES. `?view=inventory` renders the organization-wide inventory instead of the
 * hand-off surface, and `?theme=light` sets the light theme. Both exist because a browser pass has
 * to cover every surface in every theme the app actually has, and clicking through to reach one of
 * them by hand is exactly how a state stops being checked.
 */

import { useState } from "react";
import ReactDOM from "react-dom/client";
import { MemoryRouter } from "react-router-dom";

import type { EnrollmentInvitation, EnrollmentStatus, Principal } from "../api/types";
import { Sidebar } from "../components/shell/Sidebar";
import {
  EnrollmentInventoryView,
  type EnrollmentInventoryViewProps,
} from "../pages/EnrollmentInventory";
import {
  EMPTY_PAGE,
  appendPage,
  type InventoryScope,
} from "../pages/enrollment-inventory";
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
const PARAMS = new URLSearchParams(window.location.search);
const DENIED = PARAMS.get("nav") === "denied";
const INVENTORY = PARAMS.get("view") === "inventory";

// The app has exactly two themes: the dark default, and light via a root data attribute that
// remaps the semantic token layer. Both must be walked, so the harness can select either.
if (PARAMS.get("theme") === "light") {
  document.documentElement.setAttribute("data-theme", "light");
}

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
  deployment_site_label: "site-one",
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
    onRecover: () => {},
    recovering: false,
    recoverError: null,
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

const INVENTORY_PAGE = appendPage(EMPTY_PAGE, {
  items: [
    { ...STATUS, enrollment_id: ID, state: "healthy", worker_installation_id: "worker-one" },
    { ...STATUS, enrollment_id: "sha256:" + "9".repeat(64), state: "invited", worker_installation_id: "" },
    {
      ...STATUS,
      enrollment_id: "sha256:" + "8".repeat(64),
      state: "refused",
      refusal_reason: "operator_revoked",
      deployment_site_label: "site-two",
    },
    {
      ...STATUS,
      enrollment_id: "sha256:" + "7".repeat(64),
      state: "offer_transported",
      expires_at: "2026-07-30T09:00:00+00:00",
    },
  ],
  next_cursor: "opaque-cursor",
});

/** Same discipline as the hand-off harness: state moves, nothing is fetched and no controller
 *  behaviour is modelled. Load-more deliberately does nothing but toggle the busy affordance. */
function InventoryHarness() {
  const [scope, setScope] = useState<InventoryScope>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const props: EnrollmentInventoryViewProps = {
    permissions: { read: true, manage: true },
    scope,
    onScopeChange: setScope,
    page: INVENTORY_PAGE,
    loading,
    firstLoad: false,
    listError: null,
    onReload: () => {
      setLoading(true);
      window.setTimeout(() => setLoading(false), 800);
    },
    onLoadMore: () => {
      setLoading(true);
      window.setTimeout(() => setLoading(false), 800);
    },
    selectedId,
    onSelect: setSelectedId,
    onClearSelection: () => setSelectedId(null),
    onRereadSelected: () => {},
    rereading: false,
    rereadError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    onRecover: () => {},
    recovering: false,
    recoverError: null,
    liveNotice: "Loaded 4 more; 4 shown. More pages remain.",
    nowMs: NOW,
  };

  return (
    <MemoryRouter>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "16px" }}>
        <div className="shell-sidebar" style={{ flex: "none" }}>
          <Sidebar principal={PRINCIPAL} collapsed={false} />
        </div>
        <div className="app-shell__main" style={{ flex: 1, minWidth: 0, padding: "24px" }}>
          <EnrollmentInventoryView {...props} />
        </div>
      </div>
    </MemoryRouter>
  );
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  INVENTORY ? <InventoryHarness /> : <Harness />,
);
