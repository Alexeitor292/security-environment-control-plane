import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";

import { SECP_ICONS } from "../components/icons";
import { nodeIconName, nodeKindClass } from "./environments-view";
import { portsForKind, type Finding } from "./topology-workspace";

// Memoized custom nodes for the topology workspace. Rendering only — all
// semantics (ports, validation, zones) live in topology-workspace.ts.

export interface DeviceNodeData {
  kind: string;
  label: string;
  role: string | null;
  ip: string | null;
  cidr: string | null;
  findings: Finding[];
  /** True when the node exists only in the local draft (never server-owned). */
  draftLocal: boolean;
  [key: string]: unknown;
}

export interface ZoneNodeData {
  label: string;
  cidr: string | null;
  memberCount: number;
  width: number;
  height: number;
  [key: string]: unknown;
}

function findingsBadge(findings: Finding[]) {
  if (findings.length === 0) return null;
  const errors = findings.filter((f) => f.severity === "error").length;
  const cls = errors > 0 ? "tw-node__flag tw-node__flag--error" : "tw-node__flag";
  const label =
    errors > 0
      ? `${errors} validation error${errors === 1 ? "" : "s"}`
      : `${findings.length} validation warning${findings.length === 1 ? "" : "s"}`;
  return (
    <span className={cls} title={label} aria-label={label}>
      {errors > 0 ? "!" : "?"}
    </span>
  );
}

/** Host / device node (attacker, target, sensor, generic-unknown). */
export const DeviceNode = memo(function DeviceNode({
  data,
  selected,
}: NodeProps & { data: DeviceNodeData }) {
  const Icon = SECP_ICONS[nodeIconName(data.kind)];
  const kindClass = nodeKindClass(data.kind);
  const ports = portsForKind(data.kind);
  return (
    <div
      className={`tw-node tw-node--${kindClass} ${selected ? "tw-node--selected" : ""}`}
    >
      {ports.map((p) =>
        p.id === "net" || p.id === "monitor" ? (
          <Handle
            key={p.id}
            id={p.id}
            type="source"
            position={p.id === "monitor" ? Position.Right : Position.Bottom}
            className={`tw-handle tw-handle--${p.id}`}
            aria-label={p.label}
          />
        ) : (
          <Handle
            key={p.id}
            id={p.id}
            type="target"
            position={Position.Left}
            className={`tw-handle tw-handle--${p.id}`}
            aria-label={p.label}
          />
        ),
      )}
      <span className="tw-node__head">
        <Icon size={14} />
        <span className="tw-node__label">{data.label}</span>
        {findingsBadge(data.findings)}
      </span>
      <span className="tw-node__meta">
        {kindClass === "unknown" ? "unknown kind" : data.kind}
        {data.draftLocal ? " · draft" : ""}
      </span>
      {data.ip && <span className="tw-node__meta">{data.ip} (planned)</span>}
    </div>
  );
});

/** Network segment node. */
export const NetworkNode = memo(function NetworkNode({
  data,
  selected,
}: NodeProps & { data: DeviceNodeData }) {
  const Icon = SECP_ICONS["network-segment"];
  return (
    <div className={`tw-node tw-node--network ${selected ? "tw-node--selected" : ""}`}>
      <Handle
        id="members"
        type="target"
        position={Position.Top}
        className="tw-handle tw-handle--members"
        aria-label="declared members"
      />
      <span className="tw-node__head">
        <Icon size={14} />
        <span className="tw-node__label">{data.label}</span>
        {findingsBadge(data.findings)}
      </span>
      <span className="tw-node__meta">
        declared segment{data.draftLocal ? " · draft" : ""}
      </span>
      {data.cidr && <span className="tw-node__meta">{data.cidr} (planned)</span>}
    </div>
  );
});

/** Declared-zone background group. Non-interactive; label carries the
 *  declared-not-verified framing. */
export const ZoneNode = memo(function ZoneNode({ data }: NodeProps & { data: ZoneNodeData }) {
  return (
    <div
      className="tw-zone"
      style={{ width: data.width, height: data.height }}
      aria-hidden="true"
    >
      <span className="tw-zone__label">
        declared segment · {data.label}
        {data.cidr ? ` · ${data.cidr}` : ""} · {data.memberCount} member
        {data.memberCount === 1 ? "" : "s"}
      </span>
    </div>
  );
});

/** Stable nodeTypes reference (module scope — never rebuilt per render). */
export const NODE_TYPES = {
  device: DeviceNode,
  network: NetworkNode,
  zone: ZoneNode,
} as const;
