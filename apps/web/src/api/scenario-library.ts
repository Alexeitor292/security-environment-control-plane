// What `GET /api/v1/range-templates` can and cannot tell the scenario library.
//
// The reader itself already exists — `listScenarios` on `ControlPlaneReader` calls this route and
// returns `RangeTemplateOut` untouched. What was missing is the part that decides whether a page
// can be wired: which view fields have a source, which do not, and — uniquely on this page —
// which wire fields have real content and nowhere to render it.
//
// WHY THIS PAGE AND NOT THE OTHER TWO. Field coverage alone recommended Integrations twice and was
// wrong twice, because a field count cannot see two things:
//
//   ROW REALITY.  `GET /api/v1/plugins` returns exactly one row — `simulator` — because the
//                 registry bootstraps one built-in plugin and no real provider calls `register`.
//                 A page designed for eight categories renders one card, forever.
//   LAYOUT.       That page groups by `category`, which is an UNSOURCED field. The missing field
//                 is not a column, it is the axis, so even with rows there is nothing to group.
//
// This route survives both. `services/ranges.list_templates` calls `sync_catalog`, which upserts
// `range_catalog.CATALOG` — a tuple of exactly THREE templates declared in code
// (`juice-shop-solo`, `web-breach-lab`, `proxmox-web-breach-lab`). Three rows are structural, not
// deployment-dependent: a fresh database still has them, because the constant is the source.
// And the two filters the page offers — difficulty and provider — are both published.
//
// PERMISSION: none. `routers/ranges.py:126` reads `del principal  # authentication only; the
// shipped catalog is not tenant data` — the only route in the contract that states WHY it is open
// instead of leaving the absence to be inferred. Recorded as `open`, not `unknown`, on that basis.

import type { RangeTemplateOut } from "./generated/openapi";

/** The route this page reads, as keyed in `contracts/openapi/route-permissions.json`. */
export const SCENARIO_LIBRARY_ROUTE = "GET /api/v1/range-templates";

/**
 * View field <- wire field. FIVE of fourteen.
 *
 * `supportedProviders` is the one that is not a rename: the wire publishes a single `provider`
 * string and the view wants a list. Wrapping it in an array is a faithful widening — this
 * template runs on that provider — but a page must not read the singleton as "these are the
 * providers it supports", because the wire has never expressed support for more than one.
 */
export const SOURCED_FIELDS: Readonly<Record<string, string>> = {
  id: "slug",
  name: "name",
  // The one-liner, not the prose. `summary` is "One intentionally vulnerable web application on
  // its own isolated Docker network."; `description` is several sentences and has no home in the
  // view at all — see SPARE_WIRE_FIELDS.
  purpose: "summary",
  difficulty: "difficulty",
  supportedProviders: "provider (single value, widened to a one-element list)",
};

/**
 * View fields with NO source on the wire. NINE of fourteen.
 *
 * The lead's brief listed eight and included `changelog`, which is a field of `ScenarioVersion`
 * rather than of `Scenario`; it also omitted `currentVersion` and `requiredPlugins`. Counted from
 * the two type declarations rather than from the brief — the same reason the manifests gap was
 * one route and not two.
 *
 * This is a flat card list, so each of these is a per-card absence rather than a collapsed layout.
 * That is what makes the page wireable where Integrations is not: nine missing fields degrade a
 * card, one missing grouping key removes the page.
 */
export const UNSOURCED_FIELDS: readonly string[] = [
  "currentVersion",
  "estimatedCostPerHour",
  "estimatedResources",
  "requiredPlugins",
  "tags",
  "teamRange",
  "updatedAt",
  "validation",
  "versions",
];

/**
 * Wire fields with real content and nowhere to render it. SIX of eleven.
 *
 * The opposite problem, and the more interesting one — this is the only page measured so far where
 * the wire offers MORE than the view model. Every other integration has been a subtraction; this
 * one can make the page say things it currently cannot.
 *
 * An input to presentation, not a gap in the reader. Nothing here is missing; there is simply no
 * field on `Scenario` to put it in.
 */
export const SPARE_WIRE_FIELDS: readonly string[] = [
  // How many challenges the lab ships, and what they are worth. A catalogue card would normally
  // lead with these and the fixture never had them.
  "challenge_count",
  "total_points",
  // The components the template deploys — the multi-target labs are the interesting ones and the
  // view has no concept of a component at all.
  "components",
  // The long-form prose. `purpose` takes `summary`; this is the paragraph beneath it.
  "description",
  // Roughly how long a deploy takes. The view models cost per hour, which the platform does not
  // measure, and not duration, which it does.
  "estimated_deploy_seconds",
  // A per-template caution — e.g. that a lab is intentionally vulnerable. Content that arguably
  // should not be dropped silently by a page that renders the template at all.
  "warning",
];

/** The three templates the catalog constant declares. Structural, not deployment-dependent. */
export const SHIPPED_TEMPLATE_SLUGS: readonly string[] = [
  "juice-shop-solo",
  "proxmox-web-breach-lab",
  "web-breach-lab",
];

/**
 * The filters the page offers, and the wire field each reads.
 *
 * Both are published, which is the third dimension the Integrations measurement introduced: a
 * filter over a field the wire does not carry can only offer what the loaded page happens to
 * contain, which is a summary of the current rows wearing the clothes of a filter.
 */
export const FILTER_FIELDS: Readonly<Record<string, keyof RangeTemplateOut>> = {
  difficulty: "difficulty",
  provider: "provider",
};
