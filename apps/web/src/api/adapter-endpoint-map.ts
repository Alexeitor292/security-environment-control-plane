// What the spatial frontend's `ControlPlaneAdapter` asks for, and what the control plane actually
// serves. All 22 methods, each resolved against the REGISTERED route surface.
//
// HOW THIS WAS BUILT, AND WHY IT MATTERS. The route list is `contracts/openapi/openapi.json` —
// exported from the live FastAPI application by `scripts/export_openapi.py`, so it is the app's own
// answer about what is mounted: 199 paths, 230 operations. Grepping `@router` decorators would
// overstate it, because a decorated route in a module nobody calls `include_router` on is not a
// route. `adapter-endpoint-map.test.ts` re-resolves every claim below against that document, so
// this file cannot quietly drift from the API the way a prose table would.
//
// THE HEADLINE, BEFORE THE TABLE. Most of these methods return product objects with fields that
// have NO SOURCE ON THE WIRE — `Team.color`, `Team.subnet`, `Deployment.drift`,
// `Deployment.costToDate`, `InfraTarget.capacity`. An adapter that satisfies the interface
// literally has to invent them. `unsourcedFields` names every one, so a presentation layer renders
// "not available from the control plane" rather than a plausible number nobody measured. An adapter
// that fabricates is worse than no adapter: the page cannot tell the invention from the reading.
//
// A TRAP WORTH NAMING. `listEvents` does NOT map to `GET /api/v1/ranges/{range_id}/events`. The
// domain `EventItem` is a scheduled competition — phases, teams, announcements, scoring. A
// `RangeEventOut` is a LOG LINE (kind, level, message, sequence). One word, two concepts, and the
// wiring is one character away from looking right. See `secp-competitions` below for the real
// partial source.

/** How well a domain method is served by the routes that exist today. */
export type MappingStatus =
  /** An endpoint returns this entity and every domain field has a source. */
  | "exact"
  /** An endpoint returns this entity, but the domain shape differs — see `unsourcedFields`. */
  | "shaped"
  /** No registered route returns this at all. `requires` says what P7-A would have to add. */
  | "absent"
  /** Deliberately not served, and must stay that way. `requires` says why. */
  | "withheld";

export interface AdapterMapping {
  /** The `ControlPlaneAdapter` method, exactly as declared by the spatial frontend. */
  readonly method: string;
  readonly status: MappingStatus;
  /** OpenAPI paths, verbatim. Every one is re-resolved against the committed document. */
  readonly endpoints: readonly string[];
  readonly note: string;
  /**
   * Domain fields no registered endpoint supplies.
   *
   * EMPTY on an `absent` or `withheld` mapping, where it means "not applicable": nothing is
   * served at all, so there is no partial reading whose gaps need naming. Only a `shaped` mapping
   * with an empty list would be suspicious, and the test refuses that combination.
   *
   * Not a to-do list. Several of these are fields the control plane should probably never own —
   * a team's display colour is a presentation choice, not a fact about infrastructure. The point
   * is that a reader knows which numbers on a screen came off the wire and which did not.
   */
  readonly unsourcedFields: readonly string[];
  /** For `absent` and `withheld`: what would have to be added, or why it must not be. */
  readonly requires?: string;
}

/**
 * The 22 methods, in interface-declaration order.
 *
 * Pinned as a list rather than derived, because the interface lives in the spatial tree and this
 * module is in the transport layer — deliberately disjoint slices. The test asserts this set is
 * exactly the set `ADAPTER_ENDPOINT_MAP` covers, so a method added on either side surfaces here
 * instead of being served by silence.
 */
export const ADAPTER_METHODS = [
  "listEvents",
  "getEvent",
  "listScenarios",
  "getScenario",
  "listDeployments",
  "getDeployment",
  "listTeams",
  "listParticipants",
  "listAccessProfiles",
  "listTargets",
  "listWorkers",
  "listIntegrations",
  "listWorkflowRuns",
  "listApprovals",
  "listAlerts",
  "listAuditEvents",
  "listEvidence",
  "listScores",
  "listReports",
  "listUsers",
  "listSecretRefs",
  "getTopology",
] as const;

export type AdapterMethod = (typeof ADAPTER_METHODS)[number];

export const ADAPTER_ENDPOINT_MAP: readonly AdapterMapping[] = [
  {
    method: "listEvents",
    status: "absent",
    endpoints: [],
    note:
      "NOT /api/v1/ranges/{range_id}/events — that returns RangeEventOut, a log line. A domain " +
      "EventItem is a scheduled competition. A competition can be read one at a time via " +
      "/api/v1/competitions/{competition_id} or /api/v1/ranges/{range_id}/competition, but " +
      "nothing enumerates them, so there is no list to return.",
    unsourcedFields: [
      "phases",
      "announcements",
      "rules",
      "type",
      "startsAt",
      "endsAt",
      "health",
      "connectedParticipants",
      "totalParticipants",
      "description",
      "scenarioVersion",
      "deploymentIds",
    ],
    requires: "GET /api/v1/competitions (a list route). CompetitionOut carries no phases, "
      + "announcements, rules, schedule or participant counts; those need modelling first.",
  },
  {
    method: "getEvent",
    status: "shaped",
    endpoints: ["/api/v1/competitions/{competition_id}"],
    note:
      "CompetitionOut supplies id, name, range_id, state, team_count, challenge_count, "
      + "total_points, started_at, stopped_at. Everything an operator would call the EVENT — its "
      + "phases, schedule and announcements — is absent.",
    unsourcedFields: [
      "phases",
      "announcements",
      "rules",
      "type",
      "startsAt",
      "endsAt",
      "health",
      "connectedParticipants",
      "totalParticipants",
      "description",
      "scenarioVersion",
      "scoringEnabled",
    ],
  },
  {
    method: "listScenarios",
    status: "shaped",
    endpoints: ["/api/v1/range-templates"],
    note:
      "RangeTemplateOut is the closest real thing: slug, name, summary, description, difficulty, "
      + "provider, components, challenge_count, total_points, estimated_deploy_seconds, warning. "
      + "It is a catalogue entry, not a versioned scenario — there is no version history anywhere.",
    unsourcedFields: [
      "teamRange",
      "estimatedResources",
      "estimatedCostPerHour",
      "supportedProviders",
      "requiredPlugins",
      "currentVersion",
      "validation",
      "tags",
      "updatedAt",
      "versions",
    ],
  },
  {
    method: "getScenario",
    status: "shaped",
    endpoints: ["/api/v1/range-templates/{slug}"],
    note: "Same shape as listScenarios, keyed by slug rather than by an opaque id.",
    unsourcedFields: [
      "teamRange",
      "estimatedResources",
      "estimatedCostPerHour",
      "supportedProviders",
      "requiredPlugins",
      "currentVersion",
      "validation",
      "tags",
      "updatedAt",
      "versions",
    ],
  },
  {
    method: "listDeployments",
    status: "shaped",
    endpoints: ["/api/v1/ranges"],
    note:
      "RangeOut is the deployment. Its `state` is a NINE-member RangeState "
      + "(draft, deploying, ready, active, resetting, recovery_required, failed, destroying, "
      + "destroyed) against the domain's eight, and the mismatch is not cosmetic: "
      + "`recovery_required` means the range could not be OBSERVED, which is neither running nor "
      + "failed. Collapsing it into either is the substitution this programme exists to prevent. "
      + "Resources come from a second call, /api/v1/ranges/{range_id}/resources.",
    unsourcedFields: [
      "scenarioVersion",
      "eventId",
      "targetId",
      "region",
      "health",
      "drift",
      "costToDate",
      "estimatedCostPerHour",
      "expiresAt",
      "owner",
      "workflowRunIds",
    ],
  },
  {
    method: "getDeployment",
    status: "shaped",
    endpoints: ["/api/v1/ranges/{range_id}", "/api/v1/ranges/{range_id}/resources"],
    note:
      "RangeOut plus RangeResourceOut for the resource list. RangeResourceOut carries "
      + "component_key, kind, name, state, provider, image, image_digest, host_port, external_id "
      + "and removed_at — richer than DeploymentResource, and `removed_at` in particular has no "
      + "domain field, so a removed resource looks identical to a live one after mapping.",
    unsourcedFields: [
      "scenarioVersion",
      "eventId",
      "targetId",
      "region",
      "health",
      "drift",
      "costToDate",
      "estimatedCostPerHour",
      "expiresAt",
      "owner",
      "workflowRunIds",
      "resources[].ip",
      "resources[].health",
      "resources[].teamId",
    ],
  },
  {
    method: "listTeams",
    status: "shaped",
    endpoints: ["/api/v1/ranges/{range_id}/teams"],
    note:
      "SCOPING MISMATCH, and it is the load-bearing part. The method signature is "
      + "`listTeams(eventId?)` with the argument OPTIONAL; the route is range-scoped and the id is "
      + "REQUIRED. There is no route that returns teams across ranges, so the optional form cannot "
      + "be served at all. TeamOut supplies id, name, slug, score, solved_count, join_code, "
      + "competition_id — the scoreboard half. The network half is entirely absent.",
    unsourcedFields: [
      "color",
      "memberIds",
      "subnet",
      "systems",
      "connection",
      "connectedDevices",
      "gatewayHealth",
      "vpnEndpoint",
      "allowedRoutes",
      "restrictions",
      "objectives",
    ],
  },
  {
    method: "listParticipants",
    status: "shaped",
    endpoints: ["/api/v1/ranges/{range_id}/teams/{team_id}/members"],
    note:
      "Reachable only as (range, team). The signature takes `teamId?` alone, which is not enough "
      + "to build the URL, and the optional form has no route at all.",
    unsourcedFields: ["email", "role", "lastSeen"],
  },
  {
    method: "listAccessProfiles",
    status: "absent",
    endpoints: [],
    note:
      "No gateway, VPN, or participant-access surface is registered. Nothing in the 230 "
      + "operations returns a WireGuard/OpenVPN/Guacamole profile or an endpoint fingerprint.",
    unsourcedFields: [],
    requires:
      "An access-profile read surface. NOTE the shape carefully if it is ever added: the domain "
      + "type carries `publicKeyFingerprint` and no private material, which is the right line — a "
      + "profile a browser can render must never be a profile a browser could use.",
  },
  {
    method: "listTargets",
    status: "shaped",
    endpoints: ["/api/v1/targets"],
    note:
      "The cleanest mapping of the 22 at ENTITY level — TargetOut is the target — but not at "
      + "field level. Operational state (health, capacity, cost, deployment count) is not on the "
      + "target record. `secret_ref` is an opaque reference and MUST stay one: it is the presence "
      + "of a credential, never the credential.",
    unsourcedFields: [
      "location",
      "health",
      "capacity",
      "costStatus",
      "workerId",
      "credentialStatus",
      "capabilities",
      "deploymentCount",
      "lastDiscovery",
      "onboardingState",
    ],
  },
  {
    method: "listWorkers",
    status: "shaped",
    endpoints: [
      "/api/v1/target-discovery/read-only-bootstrap/worker-nodes",
      "/api/v1/enrollment",
    ],
    note:
      "TWO endpoints describe one worker between them and neither is sufficient alone. The "
      + "discovery node carries published key material; the enrollment record carries the "
      + "lifecycle state and release fingerprint. `placement-view.workerRows` already performs "
      + "exactly this join and emits a row for a worker present in only ONE of them — an enrolled "
      + "worker that never published keys, and published keys with no enrollment, are both real "
      + "states and neither may be dropped.",
    unsourcedFields: ["status", "taskQueues", "lastHeartbeat", "version", "targetIds"],
  },
  {
    method: "listIntegrations",
    status: "shaped",
    endpoints: ["/api/v1/plugins", "/api/v1/providers/capabilities"],
    note:
      "PluginOut gives name, version, capabilities, contract_version, and two booleans — "
      + "`healthy` and `simulated`. The domain wants a nine-member CapabilityStatus. "
      + "`simulated: true` is NOT 'implemented', and mapping it to anything but `simulated` "
      + "claims a capability the platform does not have. /providers/capabilities returns an "
      + "untyped object, so nothing can be read from it without a contract.",
    unsourcedFields: ["category", "detail"],
  },
  {
    method: "listWorkflowRuns",
    status: "shaped",
    endpoints: ["/api/v1/ranges/{range_id}/operations"],
    note:
      "RangeOperationOut is the real thing: kind, status, phase, percent, steps, completed_steps, "
      + "total_steps, failure_code, lease_expires_at, and `stale`/`stale_reason` — a run whose "
      + "lease expired without a terminal status, which is neither running nor failed and has NO "
      + "domain WorkflowStatus member. The declared filter is {eventId, deploymentId}; the route "
      + "is range-scoped and cannot be filtered by event.",
    unsourcedFields: ["taskQueue", "eventId", "name", "steps[].detail"],
  },
  {
    method: "listApprovals",
    status: "absent",
    endpoints: [],
    note:
      "Six approval families are registered — change-sets, plan-secret-authorizations, "
      + "plan-generation-authorizations, activation-dossiers, readonly-preflight authorizations, "
      + "resolver-activation authorizations — and EVERY one is GET-by-id only. Nothing enumerates "
      + "pending approvals, so an approvals inbox cannot be built from the current surface.",
    unsourcedFields: [],
    requires:
      "A list route per approval family, or one cross-family queue. Whatever is added must keep "
      + "the families distinct: they authorize different acts, and a single flattened 'approval' "
      + "list is how an approval for one operation gets read as authorizing another.",
  },
  {
    method: "listAlerts",
    status: "absent",
    endpoints: [],
    note:
      "No alerting surface exists. The nearest real signal is RangeEventOut.level on "
      + "/api/v1/ranges/{range_id}/events, but that is a per-range append-only log, not an alert "
      + "stream, and treating a log line as an acknowledged-able alert invents the acknowledgement.",
    unsourcedFields: [],
    requires: "An alert surface, if alerts are a product concept. `acknowledged` implies write "
      + "state the control plane does not currently hold anywhere.",
  },
  {
    method: "listAuditEvents",
    status: "shaped",
    endpoints: ["/api/v1/audit"],
    note:
      "The closest to exact of the 22. AuditEventOut supplies id, actor, action, outcome, "
      + "created_at, resource_type, resource_id and an untyped `data` blob. The domain's single "
      + "`resource` string is two fields on the wire, which is the better shape.",
    unsourcedFields: ["origin"],
  },
  {
    method: "listEvidence",
    status: "shaped",
    endpoints: [
      "/api/v1/ranges/{range_id}/teardown-evidence",
      "/api/v1/onboarding/{onboarding_id}/evidence",
      "/api/v1/target-discovery/{enrollment_id}/evidence",
    ],
    note:
      "Evidence exists in three unrelated, differently-shaped, separately-scoped places and there "
      + "is no combined feed. TeardownEvidenceOut is the richest and carries the zero-residue "
      + "proof — verdict, probe_reachable, expected_count, removed_confirmed, still_present, "
      + "unproven_count. `unproven_count` has no domain field, and folding it away turns 'nobody "
      + "could prove these are gone' into 'these are gone'.",
    unsourcedFields: ["kind", "sha256", "store", "subject"],
  },
  {
    method: "listScores",
    status: "shaped",
    endpoints: [
      "/api/v1/ranges/{range_id}/scoreboard",
      "/api/v1/competitions/{competition_id}/scoreboard",
    ],
    note:
      "SIGNATURE MISMATCH: `listScores(eventId)` takes an event id; both routes are keyed by range "
      + "or competition. ScoreboardEntryOut gives team_id, team_name, rank, score, solved_count, "
      + "solved_challenge_ids, last_solve_at. The domain's four score COMPONENTS "
      + "(defense/availability/attack/penalties) do not exist — the server holds one total, and "
      + "deriving components in the browser would be inventing the scoring model.",
    unsourcedFields: ["total", "defense", "availability", "attack", "penalties", "trend"],
  },
  {
    method: "listReports",
    status: "absent",
    endpoints: [],
    note: "No reporting surface is registered. Nothing generates, lists or stores a report.",
    unsourcedFields: [],
    requires: "A report catalogue and generation surface, if reports are in scope.",
  },
  {
    method: "listUsers",
    status: "absent",
    endpoints: [],
    note:
      "/api/v1/me returns the CURRENT principal only (user_id, email, organization_id, "
      + "permissions, is_dev_fallback). There is no user directory.",
    unsourcedFields: [],
    requires:
      "A user-directory read route. `is_dev_fallback` on the principal is worth carrying through "
      + "whatever is added: a development-fallback identity must never render as a real account.",
  },
  {
    method: "listSecretRefs",
    status: "withheld",
    endpoints: [],
    note:
      "No secret-reference surface is registered, and none should be. #115 removed the donor's "
      + "secrets-management screens for this reason.",
    unsourcedFields: [],
    requires:
      "NOTHING. This must stay unimplemented. Even a metadata-only listing puts credential "
      + "inventory — purpose, bound target, rotation schedule, lease expiry — in a browser, and "
      + "the frontend has no need for it that a per-target `secret_ref` presence flag does not "
      + "already meet. If a future brief asks for this, it should be pushed back on rather than "
      + "served.",
  },
  {
    method: "getTopology",
    status: "shaped",
    endpoints: [
      "/api/v1/instances/{instance_id}/topology",
      "/api/v1/exercises/{exercise_id}/topology",
      "/api/v1/ranges/{range_id}/proxmox/topology",
    ],
    note:
      "The two generic topology routes return UNTYPED objects — the contract publishes no shape, " +
      "so a client receives `unknown` and must narrow at runtime or not read them at all. The " +
      "Proxmox route is the typed one (ProxmoxTopologyOut), but it is provider-specific and its " +
      "`topology` member is itself an opaque document. `subjectId` is also ambiguous: three " +
      "different id spaces reach three different routes, and the method takes one string.",
    unsourcedFields: [],
  },
];

/**
 * Path segments that would name a CREDENTIAL INVENTORY route.
 *
 * `listSecretRefs` is withheld, and "withheld" only means something if somebody would notice a
 * route appearing. This is what the test checks the published contract against.
 *
 * Whole SEGMENTS, not substrings. An earlier version matched on substring and fired on
 * `/provisioning-manifests/{id}/plan-secret-readiness` — the authorization-governance family,
 * which decides whether a secret PURPOSE may be used and returns no inventory at all. A guard
 * that fires on the wrong thing gets deleted by the next person who hits it, so it was made
 * precise rather than tolerated.
 */
export const CREDENTIAL_INVENTORY_SEGMENTS: ReadonlySet<string> = new Set([
  "secrets",
  "secret-refs",
  "credentials",
  "vault",
]);

/** True when any whole segment of `path` names a credential-inventory collection. */
export function hasCredentialInventorySegment(path: string): boolean {
  return path.split("/").some((segment) => CREDENTIAL_INVENTORY_SEGMENTS.has(segment));
}

/** Convenience: every method the transport layer can serve against `main` today. */
export function servedMethods(): readonly AdapterMapping[] {
  return ADAPTER_ENDPOINT_MAP.filter((m) => m.status === "exact" || m.status === "shaped");
}

/** Every method with no route, and what P7-A would need to add. Sent to that owner directly. */
export function unservedMethods(): readonly AdapterMapping[] {
  return ADAPTER_ENDPOINT_MAP.filter((m) => m.status === "absent" || m.status === "withheld");
}
