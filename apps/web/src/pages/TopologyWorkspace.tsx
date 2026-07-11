import "@xyflow/react/dist/style.css";
import "./topology-workspace.css";

import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  applyEdgeChanges,
  applyNodeChanges,
  useReactFlow,
  type Connection,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
  type OnSelectionChangeParams,
} from "@xyflow/react";
import {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useState,
} from "react";

import type { TeamTopology } from "../api/types";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  EmptyState,
  KeyValueList,
  SafetyNotice,
} from "../components/ui";
import { SECP_ICONS } from "../components/icons";
import { edgeLegendLabel, nodeIconName } from "./environments-view";
import { NODE_TYPES, type DeviceNodeData, type ZoneNodeData } from "./topology-nodes";
import {
  EDIT_UNAVAILABLE_REASON,
  MODE_LABEL,
  PALETTE,
  SIMULATED_MODE_NOTE,
  VALIDATION_NOT_APPROVAL_NOTE,
  WORKSPACE_DECLARATIVE_NOTE,
  WORKSPACE_LOCAL_DRAFT_NOTE,
  ZONE_DECLARED_NOTE,
  connectionKind,
  displayDraftForMode,
  draftFromTopology,
  hasRecordedSimulatorState,
  initialWorkspace,
  initialWorkspaceFromDraft,
  isDraftLocalId,
  modeAllowsEditing,
  modeAvailability,
  validationStale,
  workspaceReducer,
  workspaceSummaryText,
  zonesFromDraft,
  type Draft,
  type Finding,
  type WorkspaceMode,
} from "./topology-workspace";

const NODE_W = 190;
const NODE_H = 74;
const ZONE_PAD = 28;

interface Selection {
  nodeIds: string[];
  edgeIds: string[];
}

const EMPTY_SELECTION: Selection = { nodeIds: [], edgeIds: [] };

function buildFlow(
  draft: Draft,
  findings: Finding[],
  showZones: boolean,
): { nodes: Node[]; edges: Edge[] } {
  const byNode = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.nodeId) byNode.set(f.nodeId, [...(byNode.get(f.nodeId) ?? []), f]);
  }
  const invalidEdges = new Set(
    findings.filter((f) => f.edgeId).map((f) => f.edgeId as string),
  );

  const zoneNodes: Node[] = showZones
    ? zonesFromDraft(draft)
        .filter((z) => z.memberIds.length > 0)
        .map((z) => {
          const members = draft.nodes.filter(
            (n) => z.memberIds.includes(n.id) || n.id === z.id,
          );
          const minX = Math.min(...members.map((m) => m.x)) - ZONE_PAD;
          const minY = Math.min(...members.map((m) => m.y)) - ZONE_PAD;
          const maxX = Math.max(...members.map((m) => m.x)) + NODE_W + ZONE_PAD;
          const maxY = Math.max(...members.map((m) => m.y)) + NODE_H + ZONE_PAD;
          const data: ZoneNodeData = {
            label: z.label,
            cidr: z.cidr,
            memberCount: z.memberIds.length,
            width: maxX - minX,
            height: maxY - minY,
          };
          return {
            id: `zone:${z.id}`,
            type: "zone",
            position: { x: minX, y: minY },
            data,
            draggable: false,
            selectable: false,
            focusable: false,
            zIndex: -1,
          } satisfies Node;
        })
    : [];

  const deviceNodes: Node[] = draft.nodes.map((n) => {
    const data: DeviceNodeData = {
      kind: n.kind,
      label: n.label,
      role: n.role,
      ip: n.ip,
      cidr: n.cidr,
      findings: byNode.get(n.id) ?? [],
      draftLocal: isDraftLocalId(n.id),
    };
    return {
      id: n.id,
      type: n.kind === "network" ? "network" : "device",
      position: { x: n.x, y: n.y },
      data,
    } satisfies Node;
  });

  const edges: Edge[] = draft.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.kind,
    animated: false,
    className: `tw-edge--${
      invalidEdges.has(e.id)
        ? "invalid"
        : e.kind === "monitors"
          ? "monitors"
          : e.kind === "network"
            ? "network"
            : "unknown"
    }`,
  }));

  return { nodes: [...zoneNodes, ...deviceNodes], edges };
}

function InspectorPanel({
  draft,
  selection,
  editable,
  onRename,
  onDisconnect,
}: {
  draft: Draft;
  selection: Selection;
  editable: boolean;
  onRename: (id: string, label: string) => void;
  onDisconnect: (edgeId: string) => void;
}) {
  const node =
    selection.nodeIds.length === 1
      ? draft.nodes.find((n) => n.id === selection.nodeIds[0]) ?? null
      : null;
  const edge =
    !node && selection.edgeIds.length === 1
      ? draft.edges.find((e) => e.id === selection.edgeIds[0]) ?? null
      : null;
  const [label, setLabel] = useState(node?.label ?? "");
  useEffect(() => setLabel(node?.label ?? ""), [node?.id, node?.label]);

  if (node) {
    const Icon = SECP_ICONS[nodeIconName(node.kind)];
    return (
      <CyberCard surface="well" heading="Inspector — node">
        <KeyValueList
          items={[
            {
              key: "Identity",
              value: (
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  <Icon size={13} /> {node.label}
                </span>
              ),
            },
            { key: "Kind", value: node.kind, mono: true },
            {
              key: "Source",
              value: isDraftLocalId(node.id)
                ? "local draft (not server-owned)"
                : "authoritative plan",
            },
            { key: "Planned IP", value: node.ip ?? "—", mono: node.ip !== null },
            { key: "Planned CIDR", value: node.cidr ?? "—", mono: node.cidr !== null },
            {
              key: "Relationships",
              value: String(
                draft.edges.filter((e) => e.source === node.id || e.target === node.id)
                  .length,
              ),
            },
          ]}
        />
        {editable && (
          <>
            <CyberInput
              label="Name (draft only)"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              onBlur={() => label.trim() && label !== node.label && onRename(node.id, label.trim())}
            />
            <p className="tw-note">Renames apply to the local draft only.</p>
          </>
        )}
      </CyberCard>
    );
  }
  if (edge) {
    return (
      <CyberCard surface="well" heading="Inspector — relationship">
        <KeyValueList
          items={[
            { key: "Kind", value: edgeLegendLabel(edge.kind) },
            {
              key: "From",
              value: draft.nodes.find((n) => n.id === edge.source)?.label ?? edge.source,
            },
            {
              key: "To",
              value: draft.nodes.find((n) => n.id === edge.target)?.label ?? edge.target,
            },
            {
              key: "Source",
              value: isDraftLocalId(edge.id)
                ? "local draft (not server-owned)"
                : "authoritative plan",
            },
          ]}
        />
        <p className="tw-note">
          A declared relationship — never observed traffic.
        </p>
        {editable && (
          <CyberButton variant="danger" size="sm" onClick={() => onDisconnect(edge.id)}>
            Remove relationship (draft)
          </CyberButton>
        )}
      </CyberCard>
    );
  }
  return (
    <CyberCard surface="well" heading="Inspector">
      <EmptyState title="Nothing selected">
        Select a node or relationship on the canvas.
      </EmptyState>
    </CyberCard>
  );
}

/** Additive durable-persistence layer (PR-15). When provided, the workspace is
 *  baselined from an authoritative saved revision instead of the read-only team
 *  projection, reports its draft to the persistence controller, honors an
 *  external editing gate, and renders persistence controls/panel. Absent = the
 *  PR-13 local-draft-only workspace, unchanged. */
export interface WorkspacePersistence {
  /** Reconstructed draft of the current authoritative revision. */
  authoritativeDraft: Draft;
  /** Stable key of the authoritative revision (changes trigger a rebase). */
  revisionKey: string;
  /** External editing gate (false for locked/read-only/historical postures). */
  editingEnabled: boolean;
  /** Reports the live draft + dirty/changed flags to the controller. */
  onDraftChange: (draft: Draft, dirty: boolean) => void;
  /** Persistence controls injected into the command bar. */
  toolbar?: import("react").ReactNode;
  /** Persistence panel (posture/workflow/history/conflict) below the canvas. */
  panel?: import("react").ReactNode;
}

function WorkspaceInner({
  topo,
  persistence,
}: {
  topo: TeamTopology;
  persistence?: WorkspacePersistence;
}) {
  const [state, dispatch] = useReducer(
    workspaceReducer,
    undefined,
    () =>
      persistence
        ? initialWorkspaceFromDraft(persistence.authoritativeDraft, persistence.revisionKey)
        : initialWorkspace(topo),
  );
  const [mode, setMode] = useState<WorkspaceMode>(persistence ? "edit" : "planned");
  const [selection, setSelection] = useState<Selection>(EMPTY_SELECTION);
  const [showZones, setShowZones] = useState(true);
  const [showMinimap, setShowMinimap] = useState(true);
  const [showFindings, setShowFindings] = useState(false);
  const [layoutBusy, setLayoutBusy] = useState(false);
  const flow = useReactFlow();

  const availability = modeAvailability(
    hasRecordedSimulatorState(topo.lifecycle_state),
  );
  // Editing also requires the external gate (locked/read-only/historical
  // postures set editingEnabled=false).
  const editable =
    modeAllowsEditing(mode) && (persistence?.editingEnabled ?? true);
  const stale = validationStale(state);
  const overlaysOn = mode === "validation" || showFindings;

  // Re-baseline to the authoritative revision when it changes (a save or an
  // explicit revision load), without remounting — the canvas viewport survives.
  useEffect(() => {
    if (persistence && persistence.revisionKey !== state.authoritativeKey) {
      dispatch({
        type: "rebase",
        draft: persistence.authoritativeDraft,
        key: persistence.revisionKey,
      });
      setSelection(EMPTY_SELECTION);
    }
  }, [persistence, state.authoritativeKey]);

  // Report the live draft + dirty to the persistence controller (which owns the
  // Save action). Only fires on a semantic draft change.
  const reportDraft = persistence?.onDraftChange;
  useEffect(() => {
    reportDraft?.(state.draft, state.dirty);
  }, [reportDraft, state.draft, state.dirty]);

  // Simulated mode displays ONLY the recorded authoritative projection —
  // never local draft fabrication.
  const authoritativeDraft = useMemo(() => draftFromTopology(topo), [topo]);
  const displayDraft = displayDraftForMode(mode, state.draft, authoritativeDraft);

  const built = useMemo(
    () =>
      buildFlow(
        displayDraft,
        mode !== "simulated" && overlaysOn ? state.findings : [],
        showZones,
      ),
    [displayDraft, mode, overlaysOn, state.findings, showZones],
  );

  // xyflow v12 controlled mode: the reducer stays the SEMANTIC source of
  // truth, while xyflow drives ephemeral state (live drag frames, selection)
  // through applyNodeChanges/applyEdgeChanges on this rendered copy. It is
  // re-seeded whenever the semantic graph changes, preserving selection.
  const [rfNodes, setRfNodes] = useState<Node[]>(built.nodes);
  const [rfEdges, setRfEdges] = useState<Edge[]>(built.edges);
  useEffect(() => {
    setRfNodes((prev) => {
      const selected = new Set(prev.filter((n) => n.selected).map((n) => n.id));
      return built.nodes.map((n) => ({ ...n, selected: selected.has(n.id) }));
    });
    setRfEdges((prev) => {
      const selected = new Set(prev.filter((e) => e.selected).map((e) => e.id));
      return built.edges.map((e) => ({ ...e, selected: selected.has(e.id) }));
    });
  }, [built]);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setRfNodes((ns) => applyNodeChanges(changes, ns)),
    [],
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setRfEdges((es) => applyEdgeChanges(changes, es)),
    [],
  );

  const clearSelection = useCallback(() => {
    setRfNodes((ns) => ns.map((n) => (n.selected ? { ...n, selected: false } : n)));
    setRfEdges((es) => es.map((e) => (e.selected ? { ...e, selected: false } : e)));
    setSelection(EMPTY_SELECTION);
  }, []);

  const onSelectionChange = useCallback((params: OnSelectionChangeParams) => {
    setSelection({
      nodeIds: params.nodes.map((n) => n.id),
      edgeIds: params.edges.map((e) => e.id),
    });
  }, []);

  const isValidConnection = useCallback(
    (conn: Connection | Edge) => {
      const s = state.draft.nodes.find((n) => n.id === conn.source);
      const t = state.draft.nodes.find((n) => n.id === conn.target);
      if (!s || !t) return false;
      return (
        connectionKind(
          s.kind,
          conn.sourceHandle ?? null,
          t.kind,
          conn.targetHandle ?? null,
        ) !== null
      );
    },
    [state.draft.nodes],
  );

  const onConnect = useCallback(
    (conn: Connection) => {
      if (!editable || !conn.source || !conn.target) return;
      dispatch({
        type: "connect",
        source: conn.source,
        sourceHandle: conn.sourceHandle ?? null,
        target: conn.target,
        targetHandle: conn.targetHandle ?? null,
      });
    },
    [editable],
  );

  const focusCanvas = useCallback(() => {
    document.getElementById("tw-canvas-region")?.focus();
  }, []);

  const removeSelection = useCallback(() => {
    if (!editable) return;
    dispatch({ type: "remove", nodeIds: selection.nodeIds, edgeIds: selection.edgeIds });
    setSelection(EMPTY_SELECTION);
    // Deleting the focused element must not drop focus on the floor.
    focusCanvas();
  }, [editable, selection, focusCanvas]);

  // Keyboard: undo/redo/delete/escape. Never while typing in an input.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      if (
        tag === "input" ||
        tag === "textarea" ||
        tag === "select" ||
        target?.isContentEditable
      )
        return;
      const mod = e.ctrlKey || e.metaKey;
      if (mod && !e.shiftKey && e.key.toLowerCase() === "z") {
        e.preventDefault();
        if (editable) dispatch({ type: "undo" });
      } else if (
        (mod && e.shiftKey && e.key.toLowerCase() === "z") ||
        (mod && e.key.toLowerCase() === "y")
      ) {
        e.preventDefault();
        if (editable) dispatch({ type: "redo" });
      } else if ((e.key === "Delete" || e.key === "Backspace") && editable) {
        e.preventDefault();
        removeSelection();
      } else if (e.key === "Escape") {
        clearSelection();
        setShowFindings(false);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [editable, removeSelection, clearSelection]);

  async function runLayout() {
    setLayoutBusy(true);
    try {
      const { default: ELK } = await import("elkjs/lib/elk.bundled.js");
      const elk = new ELK();
      const graph = {
        id: "root",
        layoutOptions: {
          "elk.algorithm": "layered",
          "elk.direction": "DOWN",
          "elk.spacing.nodeNode": "48",
          "elk.layered.spacing.nodeNodeBetweenLayers": "90",
        },
        children: state.draft.nodes.map((n) => ({
          id: n.id,
          width: NODE_W,
          height: NODE_H,
        })),
        edges: state.draft.edges.map((e) => ({
          id: e.id,
          sources: [e.source],
          targets: [e.target],
        })),
      };
      const res = await elk.layout(graph);
      const positions: Record<string, { x: number; y: number }> = {};
      for (const c of res.children ?? []) {
        if (c.x !== undefined && c.y !== undefined) {
          positions[c.id] = { x: c.x, y: c.y };
        }
      }
      dispatch({ type: "layout", positions });
      window.setTimeout(() => flow.fitView({ padding: 0.15 }), 30);
    } catch {
      // Malformed graphs fail safely: the draft is left untouched.
    } finally {
      setLayoutBusy(false);
    }
  }

  function focusFinding(f: Finding) {
    const edge = f.edgeId ? state.draft.edges.find((e) => e.id === f.edgeId) : null;
    // Fall back to the edge's other endpoint when one is missing (the exact
    // dangling-reference case validation exists to catch).
    const nodeId =
      f.nodeId ??
      [edge?.source, edge?.target].find((id) =>
        state.draft.nodes.some((n) => n.id === id),
      );
    const node = state.draft.nodes.find((n) => n.id === nodeId) ?? null;
    setRfNodes((ns) =>
      ns.map((n) => ({ ...n, selected: f.nodeId ? n.id === f.nodeId : false })),
    );
    setRfEdges((es) =>
      es.map((e) => ({ ...e, selected: f.edgeId ? e.id === f.edgeId : false })),
    );
    setSelection({
      nodeIds: f.nodeId ? [f.nodeId] : [],
      edgeIds: f.edgeId ? [f.edgeId] : [],
    });
    if (node) {
      flow.setCenter(node.x + NODE_W / 2, node.y + NODE_H / 2, {
        zoom: 1.1,
        duration: 250,
      });
    }
  }

  const selectedLabel =
    selection.nodeIds.length === 1
      ? state.draft.nodes.find((n) => n.id === selection.nodeIds[0])?.label ?? null
      : selection.edgeIds.length === 1
        ? `relationship ${state.draft.edges.find((e) => e.id === selection.edgeIds[0])?.kind ?? ""}`
        : null;

  const errCount = state.findings.filter((f) => f.severity === "error").length;

  return (
    <div className="tw">
      <SafetyNotice role="note" tone={editable ? "warn" : "info"}>
        {persistence
          ? editable
            ? "Edits are a local draft until you Save a new immutable revision. Saving does not validate, submit, approve, generate a plan, or deploy anything."
            : WORKSPACE_DECLARATIVE_NOTE
          : editable
            ? WORKSPACE_LOCAL_DRAFT_NOTE
            : WORKSPACE_DECLARATIVE_NOTE}
        {mode === "simulated" ? ` ${SIMULATED_MODE_NOTE}` : ""}
      </SafetyNotice>

      <div className="tw-bar" role="toolbar" aria-label="Topology workspace commands">
        <div className="tw-bar__group">
          <CyberSelect
            label="Mode"
            value={mode}
            onChange={(e) => {
              const next = e.target.value as WorkspaceMode;
              if (availability[next].available) {
                setMode(next);
                if (next === "validation") dispatch({ type: "validate" });
              }
            }}
            options={(Object.keys(MODE_LABEL) as WorkspaceMode[]).map((m) => ({
              value: m,
              label: availability[m].available
                ? MODE_LABEL[m]
                : `${MODE_LABEL[m]} — unavailable`,
              disabled: !availability[m].available,
            }))}
          />
        </div>
        <div className="tw-bar__group">
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!editable || state.past.length === 0}
            title="Undo (Ctrl+Z) — local draft only, never a backend rollback"
            onClick={() => dispatch({ type: "undo" })}
          >
            Undo
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!editable || state.future.length === 0}
            title="Redo (Ctrl+Shift+Z / Ctrl+Y)"
            onClick={() => dispatch({ type: "redo" })}
          >
            Redo
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!editable || selection.nodeIds.length + selection.edgeIds.length === 0}
            title="Delete selected (Delete) — recoverable via undo"
            onClick={removeSelection}
          >
            Delete
          </CyberButton>
        </div>
        <div className="tw-bar__group">
          <CyberButton
            variant="secondary"
            size="sm"
            onClick={() => {
              dispatch({ type: "validate" });
              setShowFindings(true);
            }}
          >
            Validate draft
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!editable || layoutBusy}
            title="Deterministic auto-layout (ELK) — user-triggered, undoable"
            onClick={runLayout}
          >
            {layoutBusy ? "Laying out…" : "Auto layout"}
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            onClick={() => flow.fitView({ padding: 0.15 })}
          >
            Fit
          </CyberButton>
        </div>
        <div className="tw-bar__group">
          <CyberButton
            variant="secondary"
            size="sm"
            aria-pressed={showZones}
            onClick={() => setShowZones((z) => !z)}
          >
            Zones
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            aria-pressed={showMinimap}
            onClick={() => setShowMinimap((m) => !m)}
          >
            Minimap
          </CyberButton>
          <CyberButton
            variant="secondary"
            size="sm"
            aria-pressed={showFindings}
            onClick={() => setShowFindings((f) => !f)}
          >
            Findings{state.findings.length > 0 ? ` (${state.findings.length})` : ""}
          </CyberButton>
        </div>
        {persistence?.toolbar && (
          <div className="tw-bar__group">{persistence.toolbar}</div>
        )}
        <span className="tw-bar__spacer" />
        <span className="tw-bar__group tw-note" aria-live="polite">
          {persistence
            ? state.dirty
              ? "local unsaved changes"
              : "matches saved revision"
            : state.dirty
              ? "local draft — unsaved (no persistence contract)"
              : "matches plan"}
          {stale ? " · validation stale" : ""}
        </span>
      </div>

      <div className="tw-body">
        <div className="tw-palette" role="group" aria-label="Palette (schema-derived)">
          {PALETTE.map((p) => {
            const Icon = SECP_ICONS[nodeIconName(p.kind)];
            return (
              <button
                key={p.kind}
                type="button"
                className="tw-palette__item"
                disabled={!editable}
                title={
                  editable
                    ? `Add a declared ${p.label.toLowerCase()} to the local draft`
                    : mode === "simulated"
                      ? EDIT_UNAVAILABLE_REASON
                      : "Switch to Edit (local draft) mode to add elements."
                }
                onClick={() =>
                  // Bounded staging strip below the plan lanes; positions wrap
                  // so added nodes never march off-canvas.
                  dispatch({
                    type: "add-node",
                    kind: p.kind,
                    x: 60 + ((state.seq * 60) % 480),
                    y: 430 + ((state.seq * 40) % 120),
                  })
                }
              >
                <Icon size={16} />
                <span>
                  {p.label}
                  <span className="tw-palette__hint">{p.hint}</span>
                </span>
              </button>
            );
          })}
          <p className="tw-note">{ZONE_DECLARED_NOTE}</p>
        </div>

        <div
          className="tw-canvas"
          role="region"
          aria-label={`Topology canvas for ${topo.team_ref}`}
          tabIndex={-1}
          id="tw-canvas-region"
        >
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={NODE_TYPES}
            fitView
            minZoom={0.2}
            maxZoom={2}
            nodesDraggable={editable}
            nodesConnectable={editable}
            elementsSelectable
            deleteKeyCode={null}
            onSelectionChange={onSelectionChange}
            isValidConnection={isValidConnection}
            onConnect={onConnect}
            onNodeDragStop={(_, node) => {
              if (editable && !node.id.startsWith("zone:")) {
                dispatch({
                  type: "move-node",
                  id: node.id,
                  x: node.position.x,
                  y: node.position.y,
                });
              }
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={24} />
            <Controls showInteractive={false} />
            {showMinimap && (
              <MiniMap
                pannable
                zoomable={false}
                nodeStrokeWidth={2}
                ariaLabel="Topology minimap"
              />
            )}
          </ReactFlow>
        </div>

        <div className="tw-inspector">
          <InspectorPanel
            draft={state.draft}
            selection={selection}
            editable={editable}
            onRename={(id, label) => dispatch({ type: "rename-node", id, label })}
            onDisconnect={(edgeId) => dispatch({ type: "disconnect", edgeId })}
          />
          {(showFindings || mode === "validation") && (
            <CyberCard
              surface="well"
              heading={`Validation findings${stale ? " (stale — re-run)" : ""}`}
            >
              {state.validatedFor === null ? (
                <p className="tw-note">Validation not run for this draft.</p>
              ) : state.findings.length === 0 ? (
                <p className="tw-note">
                  No findings. {VALIDATION_NOT_APPROVAL_NOTE}
                </p>
              ) : (
                <div className="tw-findings">
                  {state.findings.map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      className={`tw-finding tw-finding--${f.severity}`}
                      onClick={() => focusFinding(f)}
                    >
                      <span className="tw-finding__code">{f.code}</span>
                      <span className="tw-finding__msg">{f.message}</span>
                    </button>
                  ))}
                </div>
              )}
              {errCount > 0 && (
                <p className="tw-note">
                  {errCount} error{errCount === 1 ? "" : "s"} —{" "}
                  {VALIDATION_NOT_APPROVAL_NOTE}
                </p>
              )}
            </CyberCard>
          )}
        </div>
      </div>

      <CyberCard surface="well" heading="Workspace summary (text)">
        <p className="tw-summary">
          {workspaceSummaryText(displayDraft, mode, state.findings, selectedLabel)}
        </p>
        <p className="tw-note">
          Keyboard: <span className="tw-kbd">Ctrl+Z</span> undo ·{" "}
          <span className="tw-kbd">Ctrl+Shift+Z</span>/<span className="tw-kbd">Ctrl+Y</span>{" "}
          redo · <span className="tw-kbd">Delete</span> remove selected (edit mode) ·{" "}
          <span className="tw-kbd">Esc</span> clear selection.
        </p>
      </CyberCard>

      {persistence?.panel}
    </div>
  );
}

/** Cyber-range topology workspace. Without `persistence` it is the PR-13
 *  local-draft-only workspace; with it, the canvas is baselined from a durable
 *  authoring revision and the persistence controls/panel are rendered. */
export function TopologyWorkspace({
  topo,
  persistence,
}: {
  topo: TeamTopology;
  persistence?: WorkspacePersistence;
}) {
  // Key by the authoritative source so switching teams (local mode) or
  // documents (persistence mode) remounts cleanly; revision changes WITHIN a
  // document are handled by the in-place rebase effect, not a remount.
  const key = persistence ? `doc:${persistence.revisionKey.split(":")[0]}` : topo.instance_id;
  return (
    <ReactFlowProvider>
      <WorkspaceInner key={key} topo={topo} persistence={persistence} />
    </ReactFlowProvider>
  );
}
