import type { TargetCreate } from "../api/types";

export interface ProvisioningBoundaryDraft {
  allowedNodes: string;
  allowedStorage: string;
  networkSegments: string;
  cidrs: string;
  vmidStart: string;
  vmidEnd: string;
  maxTeams: string;
  maxVms: string;
  maxContainers: string;
  maxVcpu: string;
  maxMemoryMb: string;
  maxDiskGb: string;
  allowedTemplates: string;
  sizingVcpu: string;
  sizingMemoryMb: string;
  sizingDiskGb: string;
}

export const DEFAULT_PROVISIONING_BOUNDARY: ProvisioningBoundaryDraft = {
  allowedNodes: "lab-node-a",
  allowedStorage: "lab-storage-a",
  networkSegments: "lab-isolated-segment",
  cidrs: "10.60.0.0/16",
  vmidStart: "9000",
  vmidEnd: "9100",
  maxTeams: "4",
  maxVms: "20",
  maxContainers: "10",
  maxVcpu: "64",
  maxMemoryMb: "131072",
  maxDiskGb: "2048",
  allowedTemplates: "kali-linux, ubuntu-server-22.04, wazuh-agent",
  sizingVcpu: "2",
  sizingMemoryMb: "2048",
  sizingDiskGb: "20",
};

export interface RegisterTargetDraft {
  displayName: string;
  baseUrl: string;
  secretRef: string;
  boundary: ProvisioningBoundaryDraft;
}

export interface BuildResult<T> {
  ok: boolean;
  errors: string[];
  value?: T;
}

export function parseBoundaryList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseIntField(raw: string, label: string, min: number, errors: string[]): number | null {
  if (!/^\d+$/.test(raw.trim())) {
    errors.push(`${label} must be an integer >= ${min}.`);
    return null;
  }
  const value = Number.parseInt(raw.trim(), 10);
  if (value < min) {
    errors.push(`${label} must be an integer >= ${min}.`);
    return null;
  }
  return value;
}

function requiredList(raw: string, label: string, errors: string[]): string[] {
  const values = parseBoundaryList(raw);
  if (values.length === 0) errors.push(`${label} requires at least one approved value.`);
  return values;
}

function subnetPrefixFor(cidr: string): number {
  const prefix = Number.parseInt(cidr.split("/")[1] ?? "24", 10);
  return Number.isFinite(prefix) ? Math.max(prefix, 24) : 24;
}

export function buildScopePolicyFromBoundary(
  draft: ProvisioningBoundaryDraft,
): BuildResult<{ scopePolicy: Record<string, unknown>; addressSpaces: TargetCreate["address_spaces"] }> {
  const errors: string[] = [];
  const allowedNodes = requiredList(draft.allowedNodes, "Allowed nodes", errors);
  const allowedStorage = requiredList(draft.allowedStorage, "Allowed storage", errors);
  const allowedBridges = requiredList(
    draft.networkSegments,
    "Network segments / bridges",
    errors,
  );
  const allowedCidrs = requiredList(draft.cidrs, "Approved CIDR reservations", errors);
  const allowedTemplates = requiredList(draft.allowedTemplates, "Allowed templates/images", errors);

  const vmidStart = parseIntField(draft.vmidStart, "VM-ID start", 100, errors);
  const vmidEnd = parseIntField(draft.vmidEnd, "VM-ID end", 100, errors);
  if (vmidStart !== null && vmidEnd !== null && vmidEnd <= vmidStart) {
    errors.push("VM-ID end must be greater than VM-ID start.");
  }

  const maxTeams = parseIntField(draft.maxTeams, "Max teams", 1, errors);
  const maxVms = parseIntField(draft.maxVms, "Max VMs", 1, errors);
  const maxContainers = parseIntField(draft.maxContainers, "Max containers", 0, errors);
  const maxVcpu = parseIntField(draft.maxVcpu, "Max vCPU", 1, errors);
  const maxMemoryMb = parseIntField(draft.maxMemoryMb, "Max memory MB", 1, errors);
  const maxDiskGb = parseIntField(draft.maxDiskGb, "Max disk GB", 1, errors);
  const sizingVcpu = parseIntField(draft.sizingVcpu, "Default template vCPU", 1, errors);
  const sizingMemoryMb = parseIntField(
    draft.sizingMemoryMb,
    "Default template memory MB",
    128,
    errors,
  );
  const sizingDiskGb = parseIntField(draft.sizingDiskGb, "Default template disk GB", 1, errors);

  if (errors.length > 0) return { ok: false, errors };

  const nodeSizing = Object.fromEntries(
    allowedTemplates.map((template) => [
      template,
      { vcpu: sizingVcpu!, memory_mb: sizingMemoryMb!, disk_gb: sizingDiskGb! },
    ]),
  );

  return {
    ok: true,
    errors: [],
    value: {
      scopePolicy: {
        provisioning: {
          allowed_nodes: allowedNodes,
          allowed_storage: allowedStorage,
          allowed_bridges: allowedBridges,
          allowed_templates: allowedTemplates,
          vmid_range: { start: vmidStart!, end: vmidEnd! },
          max_teams: maxTeams!,
          max_vms: maxVms!,
          max_containers: maxContainers!,
          max_total_vcpu: maxVcpu!,
          max_total_memory_mb: maxMemoryMb!,
          max_total_disk_gb: maxDiskGb!,
          allowed_cidr_reservations: allowedCidrs,
          external_connectivity: { policy: "deny" },
          node_sizing: nodeSizing,
        },
      },
      addressSpaces: allowedCidrs.map((cidr) => ({
        cidr_block: cidr,
        subnet_prefix: subnetPrefixFor(cidr),
      })),
    },
  };
}

export function buildRegisterTargetPayload(
  draft: RegisterTargetDraft,
): BuildResult<TargetCreate> {
  const built = buildScopePolicyFromBoundary(draft.boundary);
  if (!built.ok || !built.value) return { ok: false, errors: built.errors };

  return {
    ok: true,
    errors: [],
    value: {
      display_name: draft.displayName,
      plugin_name: "proxmox",
      config: { base_url: draft.baseUrl, verify_tls: true },
      secret_ref: draft.secretRef || null,
      scope_policy: built.value.scopePolicy,
      address_spaces: built.value.addressSpaces,
    },
  };
}
