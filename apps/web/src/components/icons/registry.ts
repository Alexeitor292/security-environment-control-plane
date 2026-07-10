import type { SecpIconProps } from "./SecpIcon";
import {
  ApprovalIcon,
  AuditLedgerIcon,
  AuthorizationIcon,
  CandidatePlanIcon,
  CloudProviderIcon,
  ContainerIcon,
  DeploymentIcon,
  EndpointBindingIcon,
  EvidenceIcon,
  FirewallIcon,
  ImmutableHashIcon,
  KubernetesIcon,
  LocalHostingIcon,
  NetworkSegmentIcon,
  OverviewIcon,
  PacketIcon,
  ProxmoxIcon,
  RefusedIcon,
  ResolverIcon,
  RollbackIcon,
  RouterIcon,
  SealedLockIcon,
  SecpMarkIcon,
  StagingLabIcon,
  StorageIcon,
  SwitchIcon,
  TargetIcon,
  TeamIcon,
  TeardownIcon,
  TopologyIcon,
  VmIcon,
  WorkerIcon,
} from "./icons";

export type SecpIconName =
  | "secp-mark"
  | "overview"
  | "target"
  | "proxmox"
  | "kubernetes"
  | "cloud-provider"
  | "local-hosting"
  | "worker"
  | "resolver"
  | "sealed-lock"
  | "authorization"
  | "endpoint-binding"
  | "evidence"
  | "candidate-plan"
  | "immutable-hash"
  | "audit-ledger"
  | "staging-lab"
  | "deployment"
  | "topology"
  | "packet"
  | "firewall"
  | "router"
  | "switch"
  | "vm"
  | "container"
  | "storage"
  | "network-segment"
  | "team"
  | "approval"
  | "refused"
  | "rollback"
  | "teardown";

/** Typed registry. Record<SecpIconName, …> makes the compiler reject any
 *  missing/extra name, so the set stays complete. */
export const SECP_ICONS: Record<SecpIconName, (p: SecpIconProps) => JSX.Element> = {
  "secp-mark": SecpMarkIcon,
  overview: OverviewIcon,
  target: TargetIcon,
  proxmox: ProxmoxIcon,
  kubernetes: KubernetesIcon,
  "cloud-provider": CloudProviderIcon,
  "local-hosting": LocalHostingIcon,
  worker: WorkerIcon,
  resolver: ResolverIcon,
  "sealed-lock": SealedLockIcon,
  authorization: AuthorizationIcon,
  "endpoint-binding": EndpointBindingIcon,
  evidence: EvidenceIcon,
  "candidate-plan": CandidatePlanIcon,
  "immutable-hash": ImmutableHashIcon,
  "audit-ledger": AuditLedgerIcon,
  "staging-lab": StagingLabIcon,
  deployment: DeploymentIcon,
  topology: TopologyIcon,
  packet: PacketIcon,
  firewall: FirewallIcon,
  router: RouterIcon,
  switch: SwitchIcon,
  vm: VmIcon,
  container: ContainerIcon,
  storage: StorageIcon,
  "network-segment": NetworkSegmentIcon,
  team: TeamIcon,
  approval: ApprovalIcon,
  refused: RefusedIcon,
  rollback: RollbackIcon,
  teardown: TeardownIcon,
};

/** Provider glyph for a plugin/substrate kind. Neutral fallback — never a
 *  trademarked logo. */
export function providerIconName(pluginName: string | null | undefined): SecpIconName {
  switch ((pluginName ?? "").toLowerCase()) {
    case "proxmox":
      return "proxmox";
    case "kubernetes":
    case "k8s":
      return "kubernetes";
    case "aws":
    case "azure":
    case "gcp":
    case "cloud":
      return "cloud-provider";
    case "local":
    case "localhost":
      return "local-hosting";
    default:
      return "target";
  }
}
