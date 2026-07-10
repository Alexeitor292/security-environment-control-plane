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
    id: "environments",
    label: "Environments",
    items: [
      { id: "library", label: "Library", href: "/templates", end: true },
      { id: "definition-editor", label: "Definition Editor", href: "/templates/new" },
      {
        id: "exercises",
        label: "Exercises",
        unavailableReason:
          "No exercise index in this milestone — open exercises from Overview.",
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
