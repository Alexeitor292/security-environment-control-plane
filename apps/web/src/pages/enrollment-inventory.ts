// Enrollment inventory view model — pure, no React, no I/O.
//
// This is the organization-wide half of the worker-enrollment surface. It reads exactly one route,
// `GET /api/v1/enrollment`, and it reinterprets nothing: the lifecycle grouping, the id grammar and
// the expiry semantics are all reused from ./worker-enrollment, which mirrors the backend contract.
//
// THREE PROPERTIES OF THAT ROUTE SHAPE THE WHOLE MODULE, and each one is a place a plausible-looking
// interface would start lying:
//
//  1. It is a PAGE, not a set. Counting the rows that have been fetched and calling the result "your
//     organization's enrollments" would be wrong the moment a second page exists — so every count
//     here is explicitly a count of what has been loaded, and `complete` says whether that is all of
//     it.
//  2. Its order is `(expires_at, enrollment_id)` ascending, and the cursor is a keyset over exactly
//     that order. Re-sorting the accumulated rows client-side would put the rows in an order the
//     cursor does not continue, so nothing here sorts. Filtering is pushed to the server as a
//     `state` parameter for the same reason: a client-side filter over one page silently hides
//     matching rows that are on the next one.
//  3. It carries NO invitation material — the items are the same bounded status projection a
//     single-enrollment read returns. There is therefore nothing on this page to reveal, gate or
//     clear, and no code here that could grow such a thing by accident.

import type { EnrollmentStatus } from "../api/types";
import {
  ENROLLMENT_ERROR_TEXT,
  ENROLLMENT_FORWARD_STATES,
  MISSING_READ_REASON,
  expiryView,
  isTerminalState,
  siteLabelOf,
  trackedGroup,
  type EnrollmentPermissions,
  type ExpiryView,
  type Gate,
  type TrackedGroup,
} from "./worker-enrollment";

// --------------------------------------------------------------------------- scopes
//
// A scope is a server-side `state` filter with an operator-meaningful name, not a client-side view
// of one page. "Workers" and "waiting on a worker" are the two surfaces this page exists for; the
// other two exist so nothing is unreachable — a record in a state this build does not recognise can
// still only be seen under "Everything".

export const INVENTORY_SCOPES = ["workers", "queue", "attention", "all"] as const;
export type InventoryScope = (typeof INVENTORY_SCOPES)[number];

export function isInventoryScope(value: string): value is InventoryScope {
  return (INVENTORY_SCOPES as readonly string[]).includes(value);
}

/** The forward states before `healthy`: an enrollment that has been invited but has not finished. */
export const PENDING_STATES: readonly string[] = ENROLLMENT_FORWARD_STATES.filter(
  (state) => state !== "healthy",
);

/** The two terminals. Both mean no worker is enrolled; neither can be undone. */
export const ATTENTION_STATES: readonly string[] = ["refused", "recovery_required"];

/**
 * The `state` filter each scope sends. An empty array means "send no state parameter at all",
 * which is the only way to see a state this build does not know the name of — enumerating the
 * closed set into the query would make an unrecognised state permanently invisible.
 */
export function scopeStates(scope: InventoryScope): readonly string[] {
  if (scope === "workers") return ["healthy"];
  if (scope === "queue") return PENDING_STATES;
  if (scope === "attention") return ATTENTION_STATES;
  return [];
}

export const SCOPE_LABELS: Record<InventoryScope, string> = {
  workers: "Enrolled workers",
  queue: "Waiting on a worker",
  attention: "No worker enrolled",
  all: "Everything",
};

/** What each scope actually asks the controller for, in the operator's terms. */
export const SCOPE_DESCRIPTIONS: Record<InventoryScope, string> = {
  workers:
    "Enrollments that reached healthy. Each row is one worker that completed the exchange and holds a controller-issued identity.",
  queue:
    "Invitations that are open but not finished. Nothing here is waiting on you: an enrollment advances only when the worker presents the next piece of signed evidence.",
  attention:
    "Enrollments that ended without a worker — revoked, refused, or closed by the controller's expiry sweep. They are kept for audit and cannot be resumed.",
  all: "Every enrollment in your organization, in expiry order, including revoked and terminal records and any state this interface does not recognise.",
};

// --------------------------------------------------------------------------- paging
//
// The server owns the real page size and re-applies its own maximum. The clamp here exists so an
// obviously-wrong request is never sent, NOT as an authority — a response that returns a different
// number of rows than was asked for is normal and is never treated as an error.

export const PAGE_SIZE_DEFAULT = 50;
export const PAGE_SIZE_MAX = 200;

export function clampPageSize(requested: number): number {
  if (!Number.isFinite(requested)) return PAGE_SIZE_DEFAULT;
  const whole = Math.floor(requested);
  if (whole < 1) return 1;
  return whole > PAGE_SIZE_MAX ? PAGE_SIZE_MAX : whole;
}

/**
 * Everything loaded for one scope so far.
 *
 * `cursor` is opaque and is only ever echoed back. It is never parsed, compared or used to guess a
 * position, and a null cursor is the ONLY signal that the last page has been reached — the row
 * count is not, because a short page is permitted.
 */
export interface InventoryPage {
  items: readonly EnrollmentStatus[];
  cursor: string | null;
  /** How many responses have been accumulated. 0 means nothing has been loaded yet. */
  pages: number;
}

export const EMPTY_PAGE: InventoryPage = { items: [], cursor: null, pages: 0 };

/**
 * Append a response to what is already loaded, in server order.
 *
 * A duplicate id CAN legitimately arrive: a record whose `expires_at` is unchanged still moves
 * within the keyset window when concurrent writes land between two requests. The later response
 * replaces the earlier row IN PLACE so the list does not grow a second copy and does not reorder —
 * but only when it is not older, because a revision that has gone backwards is a late reply from an
 * earlier request and rendering it would walk the row backwards.
 */
export function appendPage(
  prev: InventoryPage,
  response: { items: readonly EnrollmentStatus[]; next_cursor: string | null },
): InventoryPage {
  const items = [...prev.items];
  const index = new Map<string, number>();
  items.forEach((item, i) => index.set(item.enrollment_id, i));

  for (const incoming of response.items) {
    const at = index.get(incoming.enrollment_id);
    if (at === undefined) {
      index.set(incoming.enrollment_id, items.length);
      items.push(incoming);
    } else if (incoming.revision >= items[at].revision) {
      items[at] = incoming;
    }
  }
  return { items, cursor: response.next_cursor, pages: prev.pages + 1 };
}

/** Replace one row wherever it sits, without reordering — used after a revoke or a single re-read
 *  so the table can never disagree with the detail panel about a state both have observed. */
export function replaceRow(
  page: InventoryPage,
  observed: EnrollmentStatus,
): InventoryPage {
  const at = page.items.findIndex((i) => i.enrollment_id === observed.enrollment_id);
  if (at === -1) return page;
  if (observed.revision < page.items[at].revision) return page;
  const items = [...page.items];
  items[at] = observed;
  return { ...page, items, cursor: page.cursor, pages: page.pages };
}

export function findEnrollment(
  page: InventoryPage,
  enrollmentId: string | null,
): EnrollmentStatus | null {
  if (enrollmentId === null) return null;
  return page.items.find((i) => i.enrollment_id === enrollmentId) ?? null;
}

// --------------------------------------------------------------------------- rows

export interface InventoryRow {
  enrollmentId: string;
  /** "" when this controller's projection does not carry the label. Never guessed. */
  siteLabel: string;
  state: string;
  group: TrackedGroup;
  revision: number;
  /** The raw projection timestamp, kept so the shared expiry component derives its own copy from
   *  the same value the row was judged on rather than from a re-parsed label. */
  expiresAt: string;
  expiry: ExpiryView;
  /** Past its expiry by THIS BROWSER'S clock, and not yet settled. Not a lifecycle claim. */
  pastExpiry: boolean;
  /** The enrolled worker's installation identity, or "" before the worker has bound. */
  workerInstallationId: string;
  /** Bounded lowercase code, or "". Never prose. */
  refusalReason: string;
  updatedAt: string;
}

export function inventoryRow(status: EnrollmentStatus, nowMs: number): InventoryRow {
  const expiry = expiryView(status.expires_at, nowMs);
  const group = trackedGroup(status.state);
  return {
    enrollmentId: status.enrollment_id,
    siteLabel: siteLabelOf(status),
    state: status.state,
    group,
    revision: status.revision,
    expiresAt: status.expires_at,
    expiry,
    // Settled and healthy records are never flagged: an expiry that has passed on a finished
    // enrollment says nothing about it, and flagging it would send operators chasing closed records.
    pastExpiry:
      group !== "healthy" && group !== "settled" && expiry.valid && expiry.expired,
    workerInstallationId: status.worker_installation_id,
    refusalReason: status.refusal_reason,
    updatedAt: status.updated_at,
  };
}

/** Server order is preserved exactly. Nothing here sorts — see the header. */
export function inventoryRows(
  page: InventoryPage,
  nowMs: number,
): InventoryRow[] {
  return page.items.map((item) => inventoryRow(item, nowMs));
}

// --------------------------------------------------------------------------- summary

export interface InventorySummary {
  /** Rows LOADED — never a claim about how many exist. */
  loaded: number;
  workers: number;
  queue: number;
  attention: number;
  unknown: number;
  pastExpiry: number;
  /** True only when the server said there is no next page. */
  complete: boolean;
}

export function inventorySummary(
  page: InventoryPage,
  nowMs: number,
): InventorySummary {
  const summary: InventorySummary = {
    loaded: page.items.length,
    workers: 0,
    queue: 0,
    attention: 0,
    unknown: 0,
    pastExpiry: 0,
    complete: page.pages > 0 && page.cursor === null,
  };
  for (const item of page.items) {
    const row = inventoryRow(item, nowMs);
    if (row.group === "healthy") summary.workers += 1;
    else if (row.group === "settled") summary.attention += 1;
    else if (row.group === "pending") summary.queue += 1;
    else summary.unknown += 1;
    if (row.pastExpiry) summary.pastExpiry += 1;
  }
  return summary;
}

// --------------------------------------------------------------------------- gates
//
// Usability only. The service re-checks every call and is authoritative for all of it.

const allowed: Gate = { ok: true };

export function listGate(p: EnrollmentPermissions, busy: boolean): Gate {
  if (!p.read) return { ok: false, reason: MISSING_READ_REASON };
  if (busy) return { ok: false, reason: "A request is already in flight." };
  return allowed;
}

export function loadMoreGate(
  p: EnrollmentPermissions,
  page: InventoryPage,
  busy: boolean,
): Gate {
  if (!p.read) return { ok: false, reason: MISSING_READ_REASON };
  if (page.pages === 0) return { ok: false, reason: "Load the list first." };
  if (page.cursor === null) {
    return { ok: false, reason: "Every page has been loaded." };
  }
  if (busy) return { ok: false, reason: "A request is already in flight." };
  return allowed;
}

/**
 * Revoke, offered from the inventory. It is gated on the SELECTED record rather than on a row,
 * because the request carries that record's revision and because revoking is permanent: making it a
 * one-click action in a table row would put an irreversible write one mis-aimed click away.
 */
export function inventoryRevokeGate(
  p: EnrollmentPermissions,
  selected: EnrollmentStatus | null,
  busy: boolean,
): Gate {
  if (!p.manage) {
    return {
      ok: false,
      reason:
        "Requires the enrollment:manage permission, which is separate from the enrollment:read this list uses.",
    };
  }
  if (selected === null) return { ok: false, reason: "Select an enrollment first." };
  if (isTerminalState(selected.state)) {
    return {
      ok: false,
      reason:
        selected.state === "refused"
          ? "This enrollment is already refused."
          : "This enrollment already requires recovery and cannot be revoked.",
    };
  }
  if (busy) return { ok: false, reason: "A request is already in flight." };
  return allowed;
}

// --------------------------------------------------------------------------- copy
//
// Exported constants, rendered by the page — never re-typed in JSX.

export const INVENTORY_INTRO =
  "Every enrollment in your organization: the workers that finished, the invitations still waiting on one, and the records that ended without a worker. Nothing here polls and nothing here advances an enrollment — this is a read of what the controller has recorded.";

export const ORG_SCOPE_NOTICE =
  "Scoped to your organization. Records are never readable across the organization boundary, and this page sends no organization parameter — there is nothing to widen.";

/** The most important honesty on the page: counts describe what was fetched. */
export const PARTIAL_COUNT_NOTICE =
  "These counts describe the rows loaded on this page so far, not your whole organization. Load more until the list says every page has been loaded.";

export const COMPLETE_NOTICE =
  "Every page has been loaded — these counts now cover every enrollment in your organization that matches this filter.";

export const ORDERING_NOTICE =
  "Ordered by expiry, soonest first, then by enrollment id. That order comes from the controller and is not re-sorted here: paging continues from the last row, so re-ordering the page would skip records.";

/** The controller returns a continuation whenever a page came back full, so "more to load" means
 *  "there may be more", not "there certainly are". The copy says the weaker, true thing. */
export const MORE_MAY_REMAIN_NOTICE =
  "Load more is offered whenever a page came back full, which does not guarantee another row is behind it. The last load can legitimately return nothing.";

export const FILTER_NOTICE =
  "Filtering is done by the controller, not in this browser — so a filter searches every enrollment you can see, not just the rows already loaded. Changing it starts the list again from the first page.";

export const NO_DECISION_NOTICE =
  "There is no approve or reject here, and nothing is queued for your decision. The lifecycle has no approval edge: every forward step is driven by evidence the worker signs. Revoking is the only operator write, and it is how you cancel an enrollment.";

export const SITE_LABEL_NOTICE =
  "The deployment site is an opaque grouping label chosen when the invitation was created. It is not a tenant, address, region, endpoint or provider, and it grants nothing.";

export const SITE_UNAVAILABLE_TEXT = "Not recorded";

export const STALENESS_NOTICE =
  "A snapshot from when you loaded it. Nothing refreshes on a timer — reload the list, or re-read one enrollment, to ask the controller again.";

export const SELECTION_NOTICE =
  "Details below come from the row you selected, at the revision that row was loaded at. Re-read it before acting on anything time-sensitive.";

/** The consequence of the pinned decision that enrollment:manage does not imply enrollment:read. */
export const LIST_NEEDS_READ_NOTICE =
  "Listing enrollments requires enrollment:read. enrollment:manage does not include it — an operator who can create and revoke invitations may still be unable to see this list, which is deliberate rather than a fault. Ask an organization admin for enrollment:read.";

export const SWEEP_NOTICE =
  "An unfinished enrollment past its expiry is moved to recovery required by the controller's own expiry sweep, not by this page and not by looking at it. Until the sweep runs, a row can sit past its expiry in its last state.";

export const RECOVERY_NOT_RESUMABLE_NOTICE =
  "A record that ended without a worker cannot be resumed, extended or un-revoked. Create a new invitation for that site instead; the old record stays readable for audit.";

export const NO_INVITATION_IN_LIST_NOTICE =
  "No invitation material appears on this page. The hand-off values exist only in the response that created them, and no route re-serves them — so an enrollment you have lost the invitation for must be revoked and created again.";

// --------------------------------------------------------------------------- page integrity
//
// A row the controller cannot project fails the WHOLE page rather than being dropped from it. That
// is the right call — omitting a row would tell an operator an enrollment does not exist — but it
// means a single bad record makes a whole page unreadable, and the interface has to say which of
// those two things happened. "The list is empty", "the API is unreachable" and "one row in this
// page failed its integrity check" are three different situations with three different remedies,
// and only the last of them is an administrator's problem.

/**
 * The code the controller returns when a row in the page could not be projected.
 *
 * It is `enrollment_state_corrupt` — the SAME code a single-record read returns for the record you
 * asked for. On a list it means something materially different: not "the enrollment you opened is
 * corrupt" but "one of the enrollments on this page is, and none of the page can be shown". That is
 * why the inventory layers its own copy over the shared map instead of reusing it.
 *
 * A distinct code, and the failing keyset position, are requested but NOT yet shipped — so this
 * interface deliberately offers no "skip past the bad row" control. It could not aim one.
 */
export const PAGE_INTEGRITY_CODE = "enrollment_state_corrupt";

export function isPageIntegrityFailure(code: string | null | undefined): boolean {
  return code === PAGE_INTEGRITY_CODE;
}

/** The inventory's closed-code copy: the shared map, with the page-scoped meaning layered over it. */
export const INVENTORY_ERROR_TEXT: Record<string, string> = {
  ...ENROLLMENT_ERROR_TEXT,
  [PAGE_INTEGRITY_CODE]:
    "One enrollment on this page failed its own integrity check, so the controller refused the whole page rather than quietly leaving that row out. Nothing is missing from your organization and nothing was written.",
};

/** Shown alongside that error, because the operator's next step is not obvious from the code. */
export const PAGE_INTEGRITY_STEPS: readonly string[] = [
  "The record is preserved, not repaired, and it is not deleted. This needs an administrator.",
  "No row was silently dropped — that is why the whole page refused rather than returning a shorter one.",
  "A different lifecycle filter asks for a different set of rows, and may not include the failing one.",
  "Looking an enrollment up by id on the Worker Enrollment page still works for every other record.",
];

export const EMPTY_SCOPE_TITLE = "Nothing matches this filter";

export function emptyScopeBody(scope: InventoryScope): string {
  if (scope === "workers") {
    return "No enrollment in your organization has reached healthy yet. A worker appears here once it has completed the exchange.";
  }
  if (scope === "queue") {
    return "No invitation is currently waiting on a worker. Create one from the Worker Enrollment page and hand it over.";
  }
  if (scope === "attention") {
    return "No enrollment has ended without a worker. Revoked, refused and expired-out records would appear here.";
  }
  return "Your organization has no enrollments yet.";
}
