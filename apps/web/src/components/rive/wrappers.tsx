import "./rive-motion.css";

import clsx from "clsx";
import type { ReactNode } from "react";

import { useAmbientMotion } from "../backgrounds/useAmbientMotion";
import { RiveOrFallback } from "./RiveOrFallback";
import {
  approvalVisual,
  authorizationVisual,
  bundleVisual,
  discoveryVisual,
  flowVisual,
  lockVisual,
  nodeVisual,
  type ApprovalVisual,
  type BundleVisual,
  type DiscoveryVisual,
  type FlowVisual,
  type LockVisual,
  type NodeVisual,
} from "./rive-state";

const RIVE_BASE = "/rive";

/** Shared fallback shell: a labeled decorative box whose data-state drives the
 *  SVG glyph + optional animation. The accessible label lives here (the Rive
 *  overlay is decorative), so the state stays available as text/aria. */
function Fallback({
  kind,
  state,
  label,
  size,
  children,
}: {
  kind: string;
  state: string;
  label: string;
  size: number;
  children: ReactNode;
}) {
  // Animate the fallback only when on screen, the document is visible, and
  // motion is allowed (offscreen/hidden/reduced-motion all pause it).
  const { ref, active } = useAmbientMotion<HTMLSpanElement>();
  return (
    <span
      ref={ref}
      className={clsx("rm", kind, active && "rm-animate")}
      data-state={state}
      role="img"
      aria-label={label}
      style={{ width: size, height: size }}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}
        strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {children}
      </svg>
    </span>
  );
}

// ------------------------------------------------------------ sealed lock

export interface RiveSealedLockProps {
  sealed?: boolean;
  authorized?: boolean;
  active?: boolean;
  refused?: boolean;
  label: string;
  size?: number;
}
const LOCK_LABEL: Record<LockVisual, string> = {
  sealed: "sealed",
  authorized: "authorization recorded",
  active: "active",
  refused: "refused",
};
export function RiveSealedLock(p: RiveSealedLockProps) {
  const visual = lockVisual(p);
  const size = p.size ?? 20;
  const fallback = (
    <Fallback kind="rm-lock" state={visual} size={size}
      label={`${p.label}: ${LOCK_LABEL[visual]}`}>
      <path className="rm-lock__shackle" d="M8.5 11V8.5a3.5 3.5 0 0 1 7 0V11" />
      <rect className="rm-lock__body" x="6" y="11" width="12" height="8" rx="1.5" />
      <path className="rm-lock__slash" d="M6 19 18 11" />
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/sealed-lock.riv`}
      stateMachine="LockState"
      // Inputs derived from the precedence-resolved visual (mutually exclusive)
      // so a future .riv cannot render a more-operational state than the data.
      inputs={{
        sealed: visual === "sealed",
        authorized: visual === "authorized",
        active: visual === "active",
        refused: visual === "refused",
      }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}

// -------------------------------------------------------- authorization

export interface RiveAuthorizationPulseProps {
  status: string;
  label: string;
  size?: number;
}
const AUTHZ_LABEL: Record<string, string> = {
  draft: "draft", pending: "pending", approved: "approved",
  expired: "expired", revoked: "revoked", refused: "refused",
};
export function RiveAuthorizationPulse(p: RiveAuthorizationPulseProps) {
  const visual = authorizationVisual(p.status);
  const size = p.size ?? 20;
  const fallback = (
    <Fallback kind="rm-authz" state={visual} size={size}
      label={`${p.label}: ${AUTHZ_LABEL[visual] ?? visual}`}>
      <circle className="rm-authz__ring" cx="12" cy="12" r="8" opacity="0.5" />
      <circle cx="12" cy="12" r="6" />
      <g className="rm-authz__glyph">
        <path className="rm-authz__check" d="M9 12l2 2 4-4" />
        <path className="rm-authz__clock" d="M12 9v3l2 1.5" />
        <path className="rm-authz__x" d="M9.5 9.5l5 5 M14.5 9.5l-5 5" />
        <circle className="rm-authz__dot" cx="12" cy="12" r="1.4" fill="currentColor" />
      </g>
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/authorization-pulse.riv`}
      stateMachine="AuthorizationState"
      inputs={{ status: AUTHZ_STATUS_INDEX[visual] }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}
const AUTHZ_STATUS_INDEX: Record<string, number> = {
  draft: 0, pending: 1, approved: 2, expired: 3, revoked: 4, refused: 5,
};

// -------------------------------------------------------------- packet flow

export interface RivePacketFlowProps {
  running?: boolean;
  readOnly?: boolean;
  denied?: boolean;
  sealed?: boolean;
  label: string;
  size?: number;
}
const FLOW_LABEL: Record<FlowVisual, string> = {
  sealed: "sealed — no traffic",
  "read-only": "read-only path",
  denied: "denied",
  idle: "idle",
};
export function RivePacketFlow(p: RivePacketFlowProps) {
  const visual = flowVisual(p);
  const size = p.size ?? 24;
  const fallback = (
    <Fallback kind="rm-flow" state={visual} size={size}
      label={`${p.label}: ${FLOW_LABEL[visual]}`}>
      <circle cx="5" cy="12" r="1.6" />
      <circle cx="19" cy="12" r="1.6" />
      <path className="rm-flow__track" d="M6.6 12h10.8" />
      <rect className="rm-flow__packet" x="10" y="10.4" width="3.2" height="3.2" rx="0.6" />
      <path className="rm-flow__slash" d="M6 18 18 6" />
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/packet-flow.riv`}
      stateMachine="FlowState"
      inputs={{
        running: visual === "read-only",
        readOnly: visual === "read-only",
        denied: visual === "denied",
        sealed: visual === "sealed",
      }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}

// ------------------------------------------------------------ topology node

export interface RiveTopologyNodeProps {
  selected?: boolean;
  isolated?: boolean;
  compromised?: boolean;
  sealed?: boolean;
  label: string;
  size?: number;
}
const NODE_LABEL: Record<NodeVisual, string> = {
  default: "node", selected: "selected", isolated: "isolated",
  compromised: "compromised", sealed: "sealed",
};
export function RiveTopologyNode(p: RiveTopologyNodeProps) {
  const visual = nodeVisual(p);
  const size = p.size ?? 20;
  const fallback = (
    <Fallback kind="rm-node" state={visual} size={size}
      label={`${p.label}: ${NODE_LABEL[visual]}`}>
      <circle className="rm-node__ring" cx="12" cy="12" r="9" opacity="0.5" />
      <circle className="rm-node__dash" cx="12" cy="12" r="9" />
      <rect x="7" y="7" width="10" height="10" rx="2" />
      <path className="rm-node__cross" d="M9 9l6 6 M15 9l-6 6" />
      <path className="rm-node__bar" d="M9 12h6" />
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/topology-node-state.riv`}
      stateMachine="NodeState"
      inputs={{
        selected: visual === "selected",
        isolated: visual === "isolated",
        compromised: visual === "compromised",
        sealed: visual === "sealed",
      }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}

// ------------------------------------------------------------ approval stamp

export interface RiveApprovalStampProps {
  status: string;
  label: string;
  size?: number;
}
const STAMP_LABEL: Record<ApprovalVisual, string> = {
  pending: "pending", approved: "decision recorded", rejected: "rejected", stale: "superseded",
};
export function RiveApprovalStamp(p: RiveApprovalStampProps) {
  const visual = approvalVisual(p.status);
  const size = p.size ?? 22;
  const fallback = (
    <Fallback kind="rm-stamp" state={visual} size={size}
      label={`${p.label}: ${STAMP_LABEL[visual]}`}>
      <rect x="5" y="6" width="14" height="12" rx="2" opacity="0.8" />
      <g className="rm-stamp__glyph">
        <path className="rm-stamp__check" d="M8.5 12l2 2 4-4" />
        <path className="rm-stamp__x" d="M9.5 9.5l5 5 M14.5 9.5l-5 5" />
        <path className="rm-stamp__dots" d="M9 12h.01 M12 12h.01 M15 12h.01" />
        <path className="rm-stamp__slash" d="M8 15 16 9" />
      </g>
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/approval-stamp.riv`}
      stateMachine="ApprovalState"
      inputs={{ status: STAMP_STATUS_INDEX[visual] }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}
const STAMP_STATUS_INDEX: Record<ApprovalVisual, number> = {
  pending: 0, approved: 1, rejected: 2, stale: 3,
};

// ------------------------------------------------------------ worker bundle

export interface RiveWorkerBundleProps {
  preparing?: boolean;
  ready?: boolean;
  failed?: boolean;
  sealed?: boolean;
  label: string;
  size?: number;
}
const BUNDLE_LABEL: Record<BundleVisual, string> = {
  preparing: "preparing", ready: "bundle prepared", failed: "failed", sealed: "sealed",
};
export function RiveWorkerBundle(p: RiveWorkerBundleProps) {
  const visual = bundleVisual(p);
  const size = p.size ?? 20;
  const fallback = (
    <Fallback kind="rm-bundle" state={visual} size={size}
      label={`${p.label}: ${BUNDLE_LABEL[visual]}`}>
      <path d="M5 8 12 5l7 3v8l-7 3-7-3Z" opacity="0.8" />
      <g className="rm-bundle__glyph">
        <path className="rm-bundle__check" d="M9 12l2 2 4-4" />
        <path className="rm-bundle__x" d="M9.5 9.5l5 5 M14.5 9.5l-5 5" />
        <path className="rm-bundle__lock" d="M10 13v-1.5a2 2 0 0 1 4 0V13 M9.5 13h5v3h-5Z" />
        <path className="rm-bundle__gear" d="M12 9.5v-1 M12 15.5v-1 M14.5 12h1 M8.5 12h1 M12 10.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3Z" />
      </g>
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/worker-bundle.riv`}
      stateMachine="BundleState"
      inputs={{
        preparing: visual === "preparing",
        ready: visual === "ready",
        failed: visual === "failed",
        sealed: visual === "sealed",
      }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}

// ------------------------------------------------------------ discovery scan

export interface RiveDiscoveryScanProps {
  status: string;
  label: string;
  size?: number;
}
const SCAN_LABEL: Record<DiscoveryVisual, string> = {
  queued: "queued", running: "probing", completed: "completed", failed: "failed",
};
export function RiveDiscoveryScan(p: RiveDiscoveryScanProps) {
  const visual = discoveryVisual(p.status);
  const size = p.size ?? 22;
  const fallback = (
    <Fallback kind="rm-scan" state={visual} size={size}
      label={`${p.label}: ${SCAN_LABEL[visual]}`}>
      <circle cx="12" cy="12" r="8" opacity="0.5" />
      <line className="rm-scan__beam" x1="12" y1="12" x2="12" y2="4.5" strokeWidth="2" />
      <g className="rm-scan__glyph">
        <path className="rm-scan__clock" d="M12 9v3l2 1.5" />
        <path className="rm-scan__check" d="M9 12l2 2 4-4" />
        <path className="rm-scan__x" d="M9.5 9.5l5 5 M14.5 9.5l-5 5" />
      </g>
    </Fallback>
  );
  return (
    <RiveOrFallback
      src={`${RIVE_BASE}/discovery-scan.riv`}
      stateMachine="DiscoveryState"
      inputs={{ status: SCAN_STATUS_INDEX[visual] }}
      fallback={fallback}
      width={size}
      height={size}
    />
  );
}
const SCAN_STATUS_INDEX: Record<DiscoveryVisual, number> = {
  queued: 0, running: 1, completed: 2, failed: 3,
};
