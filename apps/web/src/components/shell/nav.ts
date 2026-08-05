// Sidebar navigation model — pure data, no React.
//
// Every item either links to a route that exists today (`href`) or carries a
// truthful `unavailableReason` and renders as visibly unavailable. The shell
// never fabricates pages, counts, or status for surfaces that do not exist
// in this milestone.

export interface NavItem {
  id: string;
  label: string;
  /** Route path. Exactly one of href / unavailableReason is set. */
  href?: string;
  /** Match the route exactly (react-router `end`). */
  end?: boolean;
  /** Why this surface is not available yet — shown on the disabled item. */
  unavailableReason?: string;
  /**
   * Permissions the principal needs AT LEAST ONE of before the route is usable. Absent means the
   * item is not permission-gated, which is every item but one today.
   *
   * This is orthogonal to href / unavailableReason rather than a third alternative to them: a
   * gated item still declares an `href` and nothing else, and `resolveNavItem` turns it into one
   * or the other at render time. That deliberately leaves the model's exactly-one invariant
   * untouched — it holds for the static item AND for the resolved one.
   *
   * ANY, not ALL. Two permissions can each unlock a different part of one surface: an operator
   * with enrollment:manage but not enrollment:read can create and revoke invitations — the whole
   * hand-off flow — and is only refused status look-ups. Requiring both would hide the page from
   * the operator it was built for.
   */
  requiresAnyPermission?: readonly string[];
}

/** Fixed, actionable copy for a route the principal cannot use. It names what to ask for rather
 *  than saying "unavailable", because an operator who cannot see why has no next step. */
export function navPermissionReason(required: readonly string[]): string {
  return `Requires ${required.join(" or ")}. Ask an organization administrator to grant one.`;
}

/**
 * Resolve one nav item against the principal's permissions.
 *
 * A permitted item keeps its route; a refused one becomes a disabled entry carrying the reason,
 * reusing the affordance that already exists for surfaces this milestone does not have. It is
 * DISABLED, never hidden: the existence of an internal control-plane page is not sensitive, and
 * hiding it buys nothing while leaving the operator with no way to find out what to request.
 *
 * The result always has exactly one of href / unavailableReason, and the permitted branch returns
 * the item UNCHANGED so that guarantee is inherited from the static invariant rather than
 * re-derived. An earlier version rebuilt the item as `{ id, label, href, end }`, which silently
 * dropped `unavailableReason`: a gated item that declared a reason and no href — legal under the
 * static invariant — would have resolved to NEITHER. Unreachable with today's single gated item,
 * but the docstring promised something the code did not do, so the code was corrected rather than
 * the promise weakened.
 */
export function resolveNavItem(
  item: NavItem,
  permissions: readonly string[] | null | undefined,
): NavItem {
  const required = item.requiresAnyPermission;
  if (required === undefined || required.length === 0) return item;
  if (required.some((permission) => permissions?.includes(permission))) {
    return item;
  }
  return {
    id: item.id,
    label: item.label,
    unavailableReason: navPermissionReason(required),
  };
}

export interface NavGroup {
  id: string;
  /** Uppercase group label; null for the ungrouped top item. */
  label: string | null;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "top",
    label: null,
    items: [{ id: "overview", label: "Overview", href: "/", end: true }],
  },
  {
    id: "ranges",
    label: "Ranges",
    items: [
      { id: "range-catalog", label: "Range Catalog", href: "/ranges", end: true },
      { id: "range-create", label: "Create Range", href: "/ranges/new" },
    ],
  },
  {
    id: "environments",
    label: "Environments",
    items: [
      { id: "library", label: "Library", href: "/templates", end: true },
      { id: "definition-editor", label: "Definition Editor", href: "/templates/new" },
      {
        id: "exercises",
        label: "Exercises",
        href: "/exercises",
      },
    ],
  },
  {
    id: "infrastructure",
    label: "Infrastructure",
    items: [
      { id: "targets", label: "Targets", href: "/provider-targets" },
      { id: "onboarding", label: "Target Onboarding", href: "/onboarding" },
      { id: "discovery", label: "Target Discovery", href: "/target-discovery" },
      { id: "staging-labs", label: "Staging Labs", href: "/staging-labs" },
      {
        id: "staging-deployments",
        label: "Staging Deployments",
        href: "/staging-deployments",
      },
      // Infrastructure, not Governance: these surfaces provision a worker, and the enrollment
      // lifecycle has no approval edge — there is nothing on either to govern.
      {
        id: "worker-enrollment",
        label: "Worker Enrollment",
        href: "/worker-enrollment",
        requiresAnyPermission: ["enrollment:read", "enrollment:manage"],
      },
      // The org-wide read. Gated on enrollment:read ALONE, unlike the entry above: the list route
      // requires read, and enrollment:manage does not include it — so a manage-only principal
      // must see this entry disabled with the reason rather than open a page that can only 403.
      {
        id: "enrollment-inventory",
        label: "Enrollment Inventory",
        href: "/enrollment-inventory",
        requiresAnyPermission: ["enrollment:read"],
      },
    ],
  },
  {
    id: "governance",
    label: "Governance",
    items: [
      {
        id: "approvals",
        label: "Approvals",
        href: "/approvals",
      },
      {
        id: "readonly-preflight",
        label: "Read-Only Preflight",
        href: "/readonly-preflight",
      },
      {
        id: "resolver-activation",
        label: "Resolver Activation",
        href: "/resolver-activation",
      },
      {
        id: "ro-bootstrap",
        label: "RO Discovery Bootstrap",
        href: "/read-only-bootstrap",
      },
      { id: "audit", label: "Audit Log", href: "/audit" },
    ],
  },
  {
    id: "workflows",
    label: "Workflows",
    items: [
      {
        id: "jobs",
        label: "Jobs",
        unavailableReason: "Not available in this milestone.",
      },
      {
        id: "schedules",
        label: "Schedules",
        unavailableReason: "Not available in this milestone.",
      },
    ],
  },
  {
    id: "system",
    label: "System",
    items: [
      {
        id: "settings",
        label: "Settings",
        unavailableReason: "Not available in this milestone.",
      },
      {
        id: "plugins",
        label: "Plugins",
        unavailableReason:
          "No dedicated page in this milestone — plugin health is shown on Overview.",
      },
    ],
  },
];

/** The verbatim development disclosure carried over from the previous shell. */
export const DEV_DISCLOSURE =
  "Local development. Simulated execution only — no real infrastructure.";

/** Truthful environment label shown ahead of the disclosure. */
export const ENVIRONMENT_LABEL = "Simulated environment";
