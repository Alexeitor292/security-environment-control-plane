import type { TeamTopology } from "../api/types";
import { nodeKindClass, topologyGraph } from "./environments-view";

// Pure state model for the cyber-range topology workspace.
//
// Truth boundary:
// - The canvas renders a DECLARATIVE topology (definition/plan shape). Nodes
//   are not necessarily real machines; edges are declared relationships,
//   never observed traffic.
// - Edits are a LOCAL DRAFT ONLY: the platform exposes no topology
//   persistence contract in this milestone, so nothing here saves, and the
//   UI must never imply backend persistence.
// - Validation is deterministic client-side schema checking — valid never
//   means approved, deployable, or deployed.
// - Simulated mode surfaces recorded simulator state only; evidence mode is
//   unavailable because no durable topology evidence contract exists yet.

// ------------------------------------------------------------------ copy

export const WORKSPACE_LOCAL_DRAFT_NOTE =
  "Local draft only — the platform does not yet expose a topology persistence contract. Draft edits live in this browser session and are never sent to the backend.";

export const WORKSPACE_DECLARATIVE_NOTE =
  "Declarative topology: a node is not necessarily a real machine, and an edge is a declared relationship — never observed traffic.";

export const SIMULATED_MODE_NOTE =
  "Recorded simulator state only. Simulated is not real infrastructure, and running (simulated) is not production readiness.";

export const EVIDENCE_UNAVAILABLE_REASON =
  "No durably recorded topology evidence exists in this milestone — evidence mode stays unavailable rather than inferring observations.";

export const EDIT_UNAVAILABLE_REASON =
  "Editing is unavailable while a recorded simulator state is displayed.";

export const ZONE_DECLARED_NOTE =
  "Declared segment membership — a declared zone is not verified isolation.";

export const VALIDATION_NOT_APPROVAL_NOTE =
  "A valid draft is not an approved plan and not deployable infrastructure.";

// ------------------------------------------------------------------ modes

export type WorkspaceMode =
  | "planned"
  | "edit"
  | "validation"
  | "simulated"
  | "evidence";

export interface ModeAvailability {
  available: boolean;
  reason?: string;
}

/** Which modes are honestly available for this topology. Unsupported modes
 *  stay visible but disabled with an explanation — never fake behavior. */
export function modeAvailability(
  hasRecordedSimulatorState: boolean,
): Record<WorkspaceMode, ModeAvailability> {
  return {
    planned: { available: true },
    edit: { available: true },
    validation: { available: true },
    simulated: hasRecordedSimulatorState
      ? { available: true }
      : { available: false, reason: "No recorded simulator state for this instance." },
    evidence: { available: false, reason: EVIDENCE_UNAVAILABLE_REASON },
  };
}

/** Lifecycle states that imply a recorded simulator inventory exists. A
 *  deploying/failed/destroyed instance may have no meaningful recorded
 *  shape, so simulated mode stays honestly unavailable for those. */
export function hasRecordedSimulatorState(lifecycleState: string): boolean {
  return lifecycleState === "running" || lifecycleState === "resetting";
}

/** The draft the canvas may display for a mode. Simulated mode shows ONLY the
 *  recorded authoritative projection — never local draft fabrication. */
export function displayDraftForMode(
  mode: WorkspaceMode,
  draft: Draft,
  authoritative: Draft,
): Draft {
  return mode === "simulated" ? authoritative : draft;
}

export const MODE_LABEL: Record<WorkspaceMode, string> = {
  planned: "Planned (read-only)",
  edit: "Edit (local draft)",
  validation: "Validation",
  simulated: "Simulated (recorded state)",
  evidence: "Evidence",
};

/** Editing is only meaningful in edit mode. */
export function modeAllowsEditing(mode: WorkspaceMode): boolean {
  return mode === "edit";
}

// ------------------------------------------------------------------ draft

export interface DraftNode {
  id: string;
  kind: string;
  label: string;
  role: string | null;
  ip: string | null;
  cidr: string | null;
  x: number;
  y: number;
}

export interface DraftEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
}

export interface Draft {
  nodes: DraftNode[];
  edges: DraftEdge[];
}

/** Authoritative topology → initial draft (identity-preserving). */
export function draftFromTopology(topo: TeamTopology): Draft {
  const g = topologyGraph(topo);
  return {
    nodes: g.nodes.map((n) => ({
      id: n.id,
      kind: n.kind,
      label: n.label,
      role: n.role,
      ip: n.ip,
      cidr: n.cidr,
      x: n.x,
      y: n.y,
    })),
    edges: g.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      kind: e.kind,
    })),
  };
}

/** Stable content key for staleness checks (order-insensitive per id). */
export function draftKey(draft: Draft): string {
  const nodes = [...draft.nodes]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((n) => `${n.id}|${n.kind}|${n.label}|${n.ip ?? ""}|${n.cidr ?? ""}|${Math.round(n.x)},${Math.round(n.y)}`);
  const edges = [...draft.edges]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((e) => `${e.id}|${e.source}|${e.target}|${e.kind}`);
  return `${nodes.join(";")}#${edges.join(";")}`;
}

// ------------------------------------------------------------------ ports

/** Port model derived from the real schema relationships: hosts attach to a
 *  network; sensors declare monitoring of hosts. Nothing here represents a
 *  physical interface, and no port numbers are fabricated. */
export type PortId = "net" | "members" | "monitor" | "monitored";

export interface Port {
  id: PortId;
  label: string;
  direction: "source" | "target";
}

export function portsForKind(kind: string): Port[] {
  if (kind === "network") {
    return [{ id: "members", label: "declared members", direction: "target" }];
  }
  const ports: Port[] = [
    { id: "net", label: "network attachment (declared)", direction: "source" },
    { id: "monitored", label: "monitored by (declared)", direction: "target" },
  ];
  if (kind === "sensor") {
    ports.push({ id: "monitor", label: "monitors (declared)", direction: "source" });
  }
  return ports;
}

/**
 * Resolve a proposed connection to a declared relationship kind, or null when
 * the schema does not support it (the workspace refuses it before it ever
 * enters the draft).
 */
export function connectionKind(
  sourceKind: string,
  sourceHandle: string | null,
  targetKind: string,
  targetHandle: string | null,
): "network" | "monitors" | null {
  if (
    sourceHandle === "net" &&
    targetHandle === "members" &&
    sourceKind !== "network" &&
    targetKind === "network"
  ) {
    // "network" is the real backend edge vocabulary for segment membership.
    return "network";
  }
  if (
    sourceHandle === "monitor" &&
    targetHandle === "monitored" &&
    sourceKind === "sensor" &&
    targetKind !== "network"
  ) {
    return "monitors";
  }
  return null;
}

export function connectionRefusalReason(
  sourceKind: string,
  targetKind: string,
): string {
  if (sourceKind === "network" && targetKind === "network") {
    return "Networks cannot attach to networks in this schema.";
  }
  if (targetKind === "network") {
    return "Attach hosts to a network using the network-attachment port.";
  }
  return "Only sensors may declare monitoring of hosts.";
}

// ------------------------------------------------------------- palette

/** Palette derives from the real definition schema (role kinds + network
 *  segments). Nothing else may be created. */
export const PALETTE: { kind: string; label: string; hint: string }[] = [
  { kind: "attacker", label: "Attacker host", hint: "red-team role (declared)" },
  { kind: "target", label: "Target host", hint: "vulnerable-target role (declared)" },
  { kind: "sensor", label: "Sensor", hint: "monitoring role (declared)" },
  { kind: "network", label: "Network segment", hint: "declared segment" },
];

/** New draft-local node. The id is explicitly draft-scoped (never a
 *  server-owned identity) and no addressing/services are fabricated. */
export function newDraftNode(kind: string, seq: number, x: number, y: number): DraftNode {
  return {
    id: `draft:${kind}-${seq}`,
    kind,
    label: `${kind}-${seq}`,
    role: kind === "network" ? null : kind,
    ip: null,
    cidr: null,
    x,
    y,
  };
}

export function isDraftLocalId(id: string): boolean {
  return id.startsWith("draft:");
}

// --------------------------------------------------------------- reducer

export interface WorkspaceState {
  /** Authoritative source key (instance id); a change resets the draft. */
  authoritativeKey: string;
  draft: Draft;
  /** draftKey of the authoritative projection — dirty derives from content,
   *  so undoing every edit truthfully restores "matches plan". */
  initialKey: string;
  dirty: boolean;
  past: Draft[];
  future: Draft[];
  /** draftKey the last validation ran against (null = not run). */
  validatedFor: string | null;
  findings: Finding[];
  seq: number;
}

export const HISTORY_LIMIT = 50;

export function initialWorkspace(topo: TeamTopology): WorkspaceState {
  return initialWorkspaceFromDraft(draftFromTopology(topo), topo.instance_id);
}

const DRAFT_SEQ_RE = /^draft:.+-(\d+)$/;

/** Highest draft-local sequence already present in a draft, so a rebased
 *  workspace continues numbering above existing draft ids instead of colliding
 *  with them (a saved revision may already contain `draft:target-1`). */
function maxDraftSeq(draft: Draft): number {
  let max = 0;
  for (const n of draft.nodes) {
    const m = DRAFT_SEQ_RE.exec(n.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return max;
}

/** Build a fresh workspace whose authoritative baseline is an arbitrary draft
 *  (e.g. reconstructed from a saved revision's canonical document). `key`
 *  identifies the authoritative source so switching it resets cleanly. */
export function initialWorkspaceFromDraft(
  draft: Draft,
  key: string,
): WorkspaceState {
  return {
    authoritativeKey: key,
    draft,
    initialKey: draftKey(draft),
    dirty: false,
    past: [],
    future: [],
    validatedFor: null,
    findings: [],
    // Continue above any existing draft-local ids so a new node never reuses
    // a previously-saved draft id.
    seq: maxDraftSeq(draft) + 1,
  };
}

export type WsAction =
  | { type: "reset"; topo: TeamTopology }
  | { type: "rebase"; draft: Draft; key: string }
  | { type: "add-node"; kind: string; x: number; y: number }
  | { type: "move-node"; id: string; x: number; y: number }
  | { type: "rename-node"; id: string; label: string }
  | { type: "remove"; nodeIds: string[]; edgeIds: string[] }
  | {
      type: "connect";
      source: string;
      sourceHandle: string | null;
      target: string;
      targetHandle: string | null;
    }
  | { type: "disconnect"; edgeId: string }
  | { type: "validate" }
  | { type: "layout"; positions: Record<string, { x: number; y: number }> }
  | { type: "undo" }
  | { type: "redo" };

function pushHistory(state: WorkspaceState, next: Draft): WorkspaceState {
  return {
    ...state,
    draft: next,
    dirty: draftKey(next) !== state.initialKey,
    past: [...state.past.slice(-(HISTORY_LIMIT - 1)), state.draft],
    future: [], // a new edit invalidates redo
  };
}

/**
 * Pure workspace reducer. Only SEMANTIC operations enter history; selection
 * and viewport are component-local and never pollute undo. Undo/redo are
 * deterministic; history is bounded to HISTORY_LIMIT entries.
 */
export function workspaceReducer(
  state: WorkspaceState,
  action: WsAction,
): WorkspaceState {
  switch (action.type) {
    case "reset":
      return initialWorkspace(action.topo);

    // Re-baseline to authoritative content (a loaded or freshly-saved
    // revision). History and validation reset to the new baseline; local
    // edits are intentionally discarded by the caller's explicit action.
    case "rebase":
      return initialWorkspaceFromDraft(action.draft, action.key);

    case "add-node": {
      const node = newDraftNode(action.kind, state.seq, action.x, action.y);
      return {
        ...pushHistory(state, {
          ...state.draft,
          nodes: [...state.draft.nodes, node],
        }),
        seq: state.seq + 1,
      };
    }

    case "move-node": {
      const node = state.draft.nodes.find((n) => n.id === action.id);
      if (!node || (node.x === action.x && node.y === action.y)) return state;
      return pushHistory(state, {
        ...state.draft,
        nodes: state.draft.nodes.map((n) =>
          n.id === action.id ? { ...n, x: action.x, y: action.y } : n,
        ),
      });
    }

    case "rename-node": {
      const node = state.draft.nodes.find((n) => n.id === action.id);
      if (!node || node.label === action.label) return state;
      return pushHistory(state, {
        ...state.draft,
        nodes: state.draft.nodes.map((n) =>
          n.id === action.id ? { ...n, label: action.label } : n,
        ),
      });
    }

    case "remove": {
      if (action.nodeIds.length === 0 && action.edgeIds.length === 0) return state;
      const nodeSet = new Set(action.nodeIds);
      const edgeSet = new Set(action.edgeIds);
      return pushHistory(state, {
        nodes: state.draft.nodes.filter((n) => !nodeSet.has(n.id)),
        // removing a node removes its edges too
        edges: state.draft.edges.filter(
          (e) =>
            !edgeSet.has(e.id) && !nodeSet.has(e.source) && !nodeSet.has(e.target),
        ),
      });
    }

    case "connect": {
      const source = state.draft.nodes.find((n) => n.id === action.source);
      const target = state.draft.nodes.find((n) => n.id === action.target);
      if (!source || !target) return state;
      const kind = connectionKind(
        source.kind,
        action.sourceHandle,
        target.kind,
        action.targetHandle,
      );
      if (kind === null) return state; // refused before entering the draft
      const exists = state.draft.edges.some(
        (e) => e.source === source.id && e.target === target.id && e.kind === kind,
      );
      if (exists) return state;
      return pushHistory(state, {
        ...state.draft,
        edges: [
          ...state.draft.edges,
          {
            id: `draft:edge-${source.id}-${target.id}-${kind}`,
            source: source.id,
            target: target.id,
            kind,
          },
        ],
      });
    }

    case "disconnect": {
      if (!state.draft.edges.some((e) => e.id === action.edgeId)) return state;
      return pushHistory(state, {
        ...state.draft,
        edges: state.draft.edges.filter((e) => e.id !== action.edgeId),
      });
    }

    case "layout": {
      const changed = state.draft.nodes.some((n) => {
        const p = action.positions[n.id];
        return p && (p.x !== n.x || p.y !== n.y);
      });
      if (!changed) return state;
      // A single history entry for the whole layout application.
      return pushHistory(state, {
        ...state.draft,
        nodes: state.draft.nodes.map((n) => {
          const p = action.positions[n.id];
          return p ? { ...n, x: p.x, y: p.y } : n;
        }),
      });
    }

    case "validate":
      return {
        ...state,
        findings: validateDraft(state.draft),
        validatedFor: draftKey(state.draft),
      };

    case "undo": {
      if (state.past.length === 0) return state;
      const prev = state.past[state.past.length - 1];
      return {
        ...state,
        draft: prev,
        past: state.past.slice(0, -1),
        future: [state.draft, ...state.future].slice(0, HISTORY_LIMIT),
        dirty: draftKey(prev) !== state.initialKey,
      };
    }

    case "redo": {
      if (state.future.length === 0) return state;
      const [next, ...rest] = state.future;
      return {
        ...state,
        draft: next,
        past: [...state.past.slice(-(HISTORY_LIMIT - 1)), state.draft],
        future: rest,
        dirty: draftKey(next) !== state.initialKey,
      };
    }
  }
}

/** True when validation has not run against the current draft content. */
export function validationStale(state: WorkspaceState): boolean {
  return state.validatedFor !== null && state.validatedFor !== draftKey(state.draft);
}

// ------------------------------------------------------------ validation

export type FindingSeverity = "error" | "warning";

export interface Finding {
  id: string;
  severity: FindingSeverity;
  code: string;
  message: string;
  nodeId?: string;
  edgeId?: string;
}

const KNOWN_KINDS = new Set(["attacker", "target", "sensor", "network"]);

/** Deterministic client-side draft validation. Fixed copy only — never a
 *  backend message. Valid never implies approval or deployability. */
export function validateDraft(draft: Draft): Finding[] {
  const findings: Finding[] = [];
  const seen = new Map<string, number>();
  for (const n of draft.nodes) {
    seen.set(n.id, (seen.get(n.id) ?? 0) + 1);
  }
  for (const [id, count] of seen) {
    if (count > 1) {
      findings.push({
        id: `dup:${id}`,
        severity: "error",
        code: "duplicate_id",
        message: "Duplicate node identifier.",
        nodeId: id,
      });
    }
  }
  const nodeById = new Map(draft.nodes.map((n) => [n.id, n]));
  for (const e of draft.edges) {
    const s = nodeById.get(e.source);
    const t = nodeById.get(e.target);
    if (!s || !t) {
      findings.push({
        id: `ref:${e.id}`,
        severity: "error",
        code: "missing_reference",
        message: "Edge references a node that does not exist in the draft.",
        edgeId: e.id,
      });
      continue;
    }
    const valid =
      (e.kind === "network" && s.kind !== "network" && t.kind === "network") ||
      (e.kind === "monitors" && s.kind === "sensor" && t.kind !== "network") ||
      // "reaches" is contract-legal declared reachability between hosts
      // (intra-instance). The workspace cannot author it, but authoritative
      // plans may contain it and it must never be declared invalid.
      (e.kind === "reaches" && s.kind !== "network" && t.kind !== "network");
    if (!valid) {
      findings.push({
        id: `conn:${e.id}`,
        severity: "error",
        code: "invalid_connection",
        message: `A '${e.kind}' relationship is not valid between these node kinds.`,
        edgeId: e.id,
      });
    }
  }
  for (const n of draft.nodes) {
    if (!n.label.trim()) {
      findings.push({
        id: `name:${n.id}`,
        severity: "error",
        code: "unnamed_node",
        message: "Node has no name.",
        nodeId: n.id,
      });
    }
    if (!KNOWN_KINDS.has(n.kind)) {
      findings.push({
        id: `kind:${n.id}`,
        severity: "warning",
        code: "unknown_kind",
        message: "Unknown node kind — rendered as a generic node.",
        nodeId: n.id,
      });
      continue;
    }
    if (n.kind !== "network") {
      const attached = draft.edges.some(
        (e) => e.kind === "network" && e.source === n.id,
      );
      if (!attached) {
        findings.push({
          id: `net:${n.id}`,
          severity: "warning",
          code: "unattached_host",
          message: "Host is not attached to any declared network segment.",
          nodeId: n.id,
        });
      }
    } else {
      const members = draft.edges.some(
        (e) => e.kind === "network" && e.target === n.id,
      );
      if (!members) {
        findings.push({
          id: `empty:${n.id}`,
          severity: "warning",
          code: "empty_network",
          message: "Network segment has no declared members.",
          nodeId: n.id,
        });
      }
    }
    if (n.kind === "sensor") {
      const monitors = draft.edges.some(
        (e) => e.kind === "monitors" && e.source === n.id,
      );
      if (!monitors) {
        findings.push({
          id: `mon:${n.id}`,
          severity: "warning",
          code: "idle_sensor",
          message: "Sensor declares no monitoring relationship.",
          nodeId: n.id,
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------- zones

export interface Zone {
  id: string;
  label: string;
  cidr: string | null;
  memberIds: string[];
}

/** Declared segment zones, derived deterministically from attached edges.
 *  A zone is declared membership — never verified isolation. */
export function zonesFromDraft(draft: Draft): Zone[] {
  return draft.nodes
    .filter((n) => n.kind === "network")
    .map((net) => ({
      id: net.id,
      label: net.label,
      cidr: net.cidr,
      memberIds: draft.edges
        .filter((e) => e.kind === "network" && e.target === net.id)
        .map((e) => e.source)
        .sort(),
    }));
}

// -------------------------------------------------------------- summary

/** Accessible textual summary, synchronized with the workspace state. */
export function workspaceSummaryText(
  draft: Draft,
  mode: WorkspaceMode,
  findings: Finding[],
  selectedLabel: string | null,
): string {
  const hosts = draft.nodes.filter((n) => n.kind !== "network");
  const networks = draft.nodes.filter((n) => n.kind === "network");
  const zones = zonesFromDraft(draft);
  const errs = findings.filter((f) => f.severity === "error").length;
  const warns = findings.filter((f) => f.severity === "warning").length;
  const parts = [
    `Mode: ${MODE_LABEL[mode]}.`,
    `${hosts.length} host${hosts.length === 1 ? "" : "s"}, ${networks.length} network segment${networks.length === 1 ? "" : "s"}, ${draft.edges.length} declared relationship${draft.edges.length === 1 ? "" : "s"}.`,
    zones.length > 0
      ? `Zones: ${zones.map((z) => `${z.label} (${z.memberIds.length} member${z.memberIds.length === 1 ? "" : "s"})`).join("; ")}.`
      : "",
    hosts.length > 0
      ? `Hosts: ${hosts.map((h) => `${h.label} (${nodeKindClass(h.kind)}${h.ip ? `, planned ${h.ip}` : ""})`).join("; ")}.`
      : "",
    findings.length > 0
      ? `Validation: ${errs} error${errs === 1 ? "" : "s"}, ${warns} warning${warns === 1 ? "" : "s"}.`
      : "",
    selectedLabel ? `Selected: ${selectedLabel}.` : "",
  ];
  return parts.filter(Boolean).join(" ");
}
