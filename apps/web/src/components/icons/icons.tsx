import { SecpIcon, type SecpIconProps } from "./SecpIcon";

// Custom SECP icon set. Shared hex/cube language: a hexagon or cube frame
// carrying a compact motif. currentColor everywhere; recognizable without glow.
// Provider glyphs are neutral abstractions — no trademarked logos.

const HEX = "M12 2.6 20 7.2v9.6L12 21.4 4 16.8V7.2Z";
const CUBE_TOP = "M12 3 19 7 12 11 5 7Z";
const CUBE_SIDE = "M5 7 12 11v9l-7-4Z M19 7 12 11v9l7-4Z";

type Icon = (p: SecpIconProps) => JSX.Element;

export const SecpMarkIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <path d="M12 8.5 15.5 10.5v3L12 15.5 8.5 13.5v-3Z" />
    <path d="M8.5 10.5 12 12.5 15.5 10.5 M12 12.5V15.5" />
  </SecpIcon>
);

export const OverviewIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <path d="M8 13a4 4 0 0 1 8 0" />
    <path d="M12 13 14 10.5" />
  </SecpIcon>
);

export const TargetIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <circle cx="12" cy="12" r="3.4" />
    <circle cx="12" cy="12" r="0.6" fill="currentColor" />
  </SecpIcon>
);

export const ProxmoxIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={CUBE_TOP} />
    <path d={CUBE_SIDE} />
    <path d="M9 13.5 12 15 15 13.5" />
  </SecpIcon>
);

export const KubernetesIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <path d="M12 8v8 M8.2 10v4 M15.8 10v4 M8.2 10 12 8 15.8 10 M8.2 14 12 16 15.8 14" />
  </SecpIcon>
);

export const CloudProviderIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M7 16a3 3 0 0 1 .4-6 4.2 4.2 0 0 1 8.2 1A3 3 0 0 1 16 16Z" />
    <path d="M9.5 13.5h5" />
  </SecpIcon>
);

export const LocalHostingIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="4" y="6" width="16" height="5" rx="1.2" />
    <rect x="4" y="13" width="16" height="5" rx="1.2" />
    <path d="M7 8.5h.01 M7 15.5h.01" />
  </SecpIcon>
);

export const WorkerIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <circle cx="12" cy="10" r="2" />
    <path d="M8.5 16a3.5 3.5 0 0 1 7 0" />
  </SecpIcon>
);

export const ResolverIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <path d="M9 12h6 M9 12 11 10 M9 12 11 14 M15 12 13 10 M15 12 13 14" />
  </SecpIcon>
);

export const SealedLockIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="6" y="11" width="12" height="8" rx="1.5" />
    <path d="M8.5 11V8.5a3.5 3.5 0 0 1 7 0V11" />
    <path d="M12 14v2" />
  </SecpIcon>
);

export const AuthorizationIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="5" y="7" width="14" height="10" rx="1.5" />
    <path d="M8.5 12l2.2 2.2 4.8-4.8" />
  </SecpIcon>
);

export const EndpointBindingIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <circle cx="8" cy="12" r="2.4" />
    <circle cx="16" cy="12" r="2.4" />
    <path d="M10.4 12h3.2" />
  </SecpIcon>
);

export const EvidenceIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M7 4h7l4 4v12H7Z" />
    <path d="M14 4v4h4" />
    <path d="M9.5 13l1.5 1.5 3-3" />
  </SecpIcon>
);

export const CandidatePlanIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M7 4h10v16H7Z" />
    <path d="M10 8h4 M10 11h4 M10 14h2" />
    <path d="M14.5 16.5 16 18l2.5-2.5" />
  </SecpIcon>
);

export const ImmutableHashIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d={HEX} />
    <path d="M10 9 9.2 15 M14 9 13.2 15 M8.6 11h6 M8.2 13.5h6" />
  </SecpIcon>
);

export const AuditLedgerIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="5" y="4" width="14" height="16" rx="1.5" />
    <path d="M8.5 8h7 M8.5 11h7 M8.5 14h4" />
  </SecpIcon>
);

export const StagingLabIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M10 4v5l-3.5 7a2 2 0 0 0 1.8 2.9h7.4A2 2 0 0 0 17.5 16L14 9V4" />
    <path d="M8.5 4h7 M8.7 13h6.6" />
  </SecpIcon>
);

export const DeploymentIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M13 4c3 1 4 4 4 7l-3 3-3.5-.5L8 13c0-3 2-6 5-9Z" />
    <circle cx="14" cy="9" r="1.4" />
    <path d="M8 16l-2 2 M10 18l-2 2" />
  </SecpIcon>
);

export const TopologyIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <circle cx="12" cy="6" r="2" />
    <circle cx="6" cy="17" r="2" />
    <circle cx="18" cy="17" r="2" />
    <path d="M12 8v3 M12 11 7 15.5 M12 11 17 15.5" />
  </SecpIcon>
);

export const PacketIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="7" y="9" width="10" height="6" rx="1" />
    <path d="M3 12h4 M17 12h4" />
  </SecpIcon>
);

export const FirewallIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="5" y="6" width="14" height="12" rx="1" />
    <path d="M5 10h14 M5 14h14 M9.5 6v4 M14.5 6v4 M12 10v4 M7 14v4 M17 14v4" />
  </SecpIcon>
);

export const RouterIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="4" y="13" width="16" height="5" rx="1.2" />
    <path d="M7 16h.01 M12 13v-3 M12 10l2.5-2.5 M12 10 9.5 7.5" />
  </SecpIcon>
);

export const SwitchIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="4" y="9" width="16" height="6" rx="1.2" />
    <path d="M7 12h.01 M10 12h.01 M13 12h.01 M16 12h.01" />
  </SecpIcon>
);

export const VmIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <rect x="5" y="6" width="14" height="9" rx="1.2" />
    <path d="M9 18h6 M12 15v3" />
  </SecpIcon>
);

export const ContainerIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M5 8 12 5l7 3v8l-7 3-7-3Z" />
    <path d="M12 5v14 M5 8l7 3 7-3" />
  </SecpIcon>
);

export const StorageIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <ellipse cx="12" cy="7" rx="6" ry="2.4" />
    <path d="M6 7v10c0 1.3 2.7 2.4 6 2.4s6-1.1 6-2.4V7" />
    <path d="M6 12c0 1.3 2.7 2.4 6 2.4s6-1.1 6-2.4" />
  </SecpIcon>
);

export const NetworkSegmentIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M4 8h16 M4 16h16" strokeDasharray="3 2.5" />
    <circle cx="9" cy="12" r="1.4" />
    <circle cx="15" cy="12" r="1.4" />
    <path d="M10.4 12h3.2" />
  </SecpIcon>
);

export const TeamIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <circle cx="9" cy="9.5" r="2" />
    <circle cx="15" cy="9.5" r="2" />
    <path d="M5.5 17a3.5 3.5 0 0 1 7 0 M11.5 17a3.5 3.5 0 0 1 7 0" />
  </SecpIcon>
);

export const ApprovalIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M6 12l1.5 6h9L18 12" />
    <path d="M12 4v8 M9 7l3-3 3 3" />
  </SecpIcon>
);

export const RefusedIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <circle cx="12" cy="12" r="8" />
    <path d="M9 9l6 6 M15 9l-6 6" />
  </SecpIcon>
);

export const RollbackIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M6 12a6 6 0 1 0 2-4.5" />
    <path d="M5 5v3h3" />
  </SecpIcon>
);

export const TeardownIcon: Icon = (p) => (
  <SecpIcon {...p}>
    <path d="M6 8h12l-1 11H7Z" />
    <path d="M9.5 8V6h5v2 M10 11v5 M14 11v5" />
  </SecpIcon>
);
