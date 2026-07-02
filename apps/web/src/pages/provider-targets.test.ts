import { describe, expect, it } from "vitest";

import {
  DEFAULT_PROVISIONING_BOUNDARY,
  buildRegisterTargetPayload,
  buildScopePolicyFromBoundary,
} from "./provider-targets";

describe("Provider Targets provisioning boundary", () => {
  it("creates a usable demo-safe scope policy for target registration", () => {
    const result = buildRegisterTargetPayload({
      displayName: "Lab target",
      baseUrl: "https://proxmox.example.test:8006/api2/json",
      secretRef: "env:SECP_PROVIDER_SECRET__LAB",
      boundary: DEFAULT_PROVISIONING_BOUNDARY,
    });

    expect(result.ok).toBe(true);
    const payload = result.value!;
    const provisioning = payload.scope_policy!.provisioning as Record<string, any>;
    expect(provisioning.allowed_nodes).toEqual(["lab-node-a"]);
    expect(provisioning.allowed_storage).toEqual(["lab-storage-a"]);
    expect(provisioning.allowed_bridges).toEqual(["lab-isolated-segment"]);
    expect(provisioning.allowed_cidr_reservations).toEqual(["10.60.0.0/16"]);
    expect(provisioning.vmid_range).toEqual({ start: 9000, end: 9100 });
    expect(provisioning.external_connectivity).toEqual({ policy: "deny" });
    expect(provisioning.allowed_templates).toEqual([
      "kali-linux",
      "ubuntu-server-22.04",
      "wazuh-agent",
    ]);
    expect(provisioning.node_sizing).toEqual({
      "kali-linux": { vcpu: 2, memory_mb: 2048, disk_gb: 20 },
      "ubuntu-server-22.04": { vcpu: 2, memory_mb: 2048, disk_gb: 20 },
      "wazuh-agent": { vcpu: 2, memory_mb: 2048, disk_gb: 20 },
    });
    expect(payload.address_spaces).toEqual([
      { cidr_block: "10.60.0.0/16", subnet_prefix: 24 },
    ]);
  });

  it("refuses an empty approved network segment list before posting", () => {
    const result = buildScopePolicyFromBoundary({
      ...DEFAULT_PROVISIONING_BOUNDARY,
      networkSegments: "",
    });

    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.includes("Network segments / bridges"))).toBe(true);
  });
});
