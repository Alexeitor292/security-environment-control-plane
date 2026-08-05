// A worked example of the Proxmox Web Breach Lab.
//
// NOTHING HERE IS A READING OF ANY CLUSTER. No Proxmox host was contacted to produce a single
// value. The addresses, MACs, VMIDs and hashes are invented, drawn from the documented pools in
// `proxmox_ipam.IpamPools` so the shapes are right and the numbers are obviously synthetic.
//
// Every export is declared `OfflineRecord<T>` — a narrower type than `Sourced<T>` — so none of it
// can be passed where a live reading is required. `provenance.test.ts` re-checks every export at
// runtime, iterating the namespace so a fixture added later is covered without anyone remembering.
//
// TWO KINDS OF FIXTURE LIVE HERE, and the difference is load-bearing:
//
//   Those typed against the GENERATED contract (`ProxmoxAllocationOut`, `IsolationFindingOut`,
//   `ReadinessFindingOut`) model a shape the API really publishes. They compile only while they
//   agree with `contracts/openapi/openapi.json`, so a contract change breaks them rather than
//   leaving them quietly modelling a response the server stopped sending.
//
//   Those typed against `src/api/recorded-documents.ts` model WORKER documents — the OpenTofu plan
//   document, the gate's authoritative state, the emitted authorizations, the verification report.
//   The API carries these inside opaque `dict[str, Any]` members or does not carry them at all, so
//   nothing generated can check them and they stay what they have always been: a careful reading
//   of the Python, kept honest by the `modelledOn` string on every record.
//
// The `reason` on each record says which case it is in. It is rendered, so a reviewer never has to
// take a panel's word for where its numbers came from.

import { offlineFixture, type OfflineRecord } from "./provenance";
import type {
  AbsenceFinding,
  ApplyAuthorization,
  AuthoritativeState,
  CompiledTopology,
  DeletionSet,
  DestroyApproval,
  DestroyPreconditions,
  GuestSpec,
  IpamPools,
  Ownership,
  PlanDocument,
  ReconcileDecision,
  ResetPlan,
  ReviewedGuestImage,
  VerificationReport,
  WorkerIdentity,
  ZeroResidueProof,
} from "../../api/recorded-documents";
import {
  DESTROY_OPERATION_KIND,
  EXECUTION_STATUS_NOT_APPLIED,
  INFRASTRUCTURE_OPERATOR_ROLE,
  PLAN_DOCUMENT_VERSION,
} from "../../api/recorded-documents";
// Shapes the contract DOES type come from the generated contract, so a fixture that drifts from
// the API stops compiling rather than quietly modelling a shape the server never sends.
import type {
  IsolationFindingOut,
  ProxmoxAllocationOut,
  ReadinessFindingOut,
} from "../../api/generated/openapi";
import type {
  ApplyAuthorizationState,
  DestroyAuthorizationState,
  PlanApprovalState,
} from "./proxmox-view";

// The default reason. It is deliberately about what this VALUE is, not about what the API lacks:
// #112 gave most of these shapes an endpoint, and a reason that claimed otherwise would be exactly
// the stale prose this repository keeps getting bitten by.
const OFFLINE_EXAMPLE =
  "A worked example compiled into this build. No Proxmox cluster was contacted to produce it. Where an endpoint publishes this shape, the endpoint is what a surface must read — this record exists to exercise the projection under test, never to stand in for a reading.";

const ORG = "org-7f3a";
const TARGET = "tgt-pve-lab-01";
const RANGE = "rng-web-breach-01";
const GENERATION = 3;
const OPERATION_GENERATION = 5;

/** Obviously synthetic: a real fingerprint is not a repeated nibble. */
function fakeHash(nibble: string): string {
  return `sha256:${nibble.repeat(64)}`;
}

function ownership(resourceKind: string, teamRef: string | null = null): Ownership {
  return {
    organization_id: ORG,
    target_id: TARGET,
    range_id: RANGE,
    generation: GENERATION,
    operation_generation: OPERATION_GENERATION,
    resource_kind: resourceKind,
    team_ref: teamRef,
  };
}

// --------------------------------------------------------------------------------- topology

function guest(
  ref: string,
  name: string,
  vmid: number,
  node: string,
  team: string,
  vnet: string,
  mac: string,
  address: string,
  probe: string | null,
  template: string,
  cpu: number,
  memoryMb: number,
  diskGb: number,
  storage: string,
  kind: "qemu" | "lxc",
): GuestSpec {
  return {
    guest_ref: ref,
    name,
    kind,
    vmid,
    node_name: node,
    template_ref: template,
    clone_strategy: "full",
    cpu_cores: cpu,
    memory_mb: memoryMb,
    disks: [
      { slot: "scsi0", size_gb: diskGb, storage_id: storage, discard: true, ssd_emulation: false },
    ],
    nics: [{ index: 0, vnet_name: vnet, mac_address: mac, model: "virtio", firewall: true }],
    address: { published_address: address, probe_address: probe },
    ownership: ownership("container", team),
    start_on_deploy: true,
    readiness_timeout_seconds: 300,
  };
}

const TOPOLOGY: CompiledTopology = {
  target: {
    target_id: TARGET,
    cluster_name: "pve-lab",
    cluster_fingerprint: fakeHash("c"),
    management_cidrs: ["10.20.0.0/24"],
    management_bridges: ["vmbr0"],
  },
  ownership: ownership("network"),
  network: {
    zone: {
      name: "secpz9a1",
      bridge: "vmbr1",
      nodes: ["pve-node-1", "pve-node-2"],
      ownership: ownership("network"),
      mtu: 1450,
    },
    vnets: [
      {
        name: "secpv1a01",
        zone_name: "secpz9a1",
        vlan_tag: 1101,
        subnet: { cidr: "10.80.16.0/24", gateway: "10.80.16.1", routed: false },
        role: "attacker",
        ownership: ownership("network", "team-alpha"),
        alias: "alpha attack",
      },
      {
        name: "secpv1a02",
        zone_name: "secpz9a1",
        vlan_tag: 1102,
        subnet: { cidr: "10.80.17.0/24", gateway: "10.80.17.1", routed: false },
        role: "vulnerable",
        ownership: ownership("network", "team-alpha"),
        alias: "alpha targets",
      },
      {
        name: "secpv1b01",
        zone_name: "secpz9a1",
        vlan_tag: 1103,
        subnet: { cidr: "10.80.18.0/24", gateway: "10.80.18.1", routed: false },
        role: "attacker",
        ownership: ownership("network", "team-bravo"),
        alias: "bravo attack",
      },
      {
        name: "secpv1b02",
        zone_name: "secpz9a1",
        vlan_tag: 1104,
        subnet: { cidr: "10.80.19.0/24", gateway: "10.80.19.1", routed: false },
        role: "vulnerable",
        ownership: ownership("network", "team-bravo"),
        alias: "bravo targets",
      },
      {
        name: "secpv1s00",
        zone_name: "secpz9a1",
        vlan_tag: 1100,
        subnet: { cidr: "10.80.15.0/24", gateway: "10.80.15.1", routed: true },
        role: "scoring",
        ownership: ownership("network"),
        alias: "scoring",
      },
    ],
    security_groups: [
      {
        name: "secpg1a01",
        ownership: ownership("network", "team-alpha"),
        comment: "alpha segment policy",
        rules: [
          {
            position: 0,
            direction: "OUT",
            verdict: "ACCEPT",
            comment: "scoring submission",
            source: "10.80.16.0/24",
            dest: "10.80.15.0/24",
            proto: "tcp",
            dport: "443",
            enabled: true,
          },
          {
            position: 1,
            direction: "OUT",
            verdict: "DROP",
            comment: "management plane unreachable",
            source: null,
            dest: "10.20.0.0/24",
            proto: null,
            dport: null,
            enabled: true,
          },
          {
            position: 2,
            direction: "OUT",
            verdict: "DROP",
            comment: "cross-team denial",
            source: null,
            dest: "10.80.18.0/23",
            proto: null,
            dport: null,
            enabled: true,
          },
          {
            position: 3,
            direction: "OUT",
            verdict: "DROP",
            comment: "default deny — no public route",
            source: null,
            dest: null,
            proto: null,
            dport: null,
            enabled: true,
          },
        ],
      },
      {
        name: "secpg1b01",
        ownership: ownership("network", "team-bravo"),
        comment: "bravo segment policy",
        rules: [
          {
            position: 0,
            direction: "OUT",
            verdict: "ACCEPT",
            comment: "scoring submission",
            source: "10.80.18.0/24",
            dest: "10.80.15.0/24",
            proto: "tcp",
            dport: "443",
            enabled: true,
          },
          {
            position: 1,
            direction: "OUT",
            verdict: "DROP",
            comment: "management plane unreachable",
            source: null,
            dest: "10.20.0.0/24",
            proto: null,
            dport: null,
            enabled: true,
          },
          {
            position: 2,
            direction: "OUT",
            verdict: "DROP",
            comment: "cross-team denial",
            source: null,
            dest: "10.80.16.0/23",
            proto: null,
            dport: null,
            enabled: true,
          },
          {
            position: 3,
            direction: "OUT",
            verdict: "DROP",
            comment: "default deny — no public route",
            source: null,
            dest: null,
            proto: null,
            dport: null,
            enabled: true,
          },
        ],
      },
    ],
    ip_sets: [
      {
        name: "secpi1m00",
        cidrs: ["10.20.0.0/24"],
        ownership: ownership("network"),
        comment: "management plane — always denied",
      },
      {
        name: "secpi1s00",
        cidrs: ["10.80.15.0/24"],
        ownership: ownership("network"),
        comment: "scoring segment",
      },
    ],
    vnet_security_group: {
      secpv1a01: "secpg1a01",
      secpv1a02: "secpg1a01",
      secpv1b01: "secpg1b01",
      secpv1b02: "secpg1b01",
    },
    // No approved egress in this example. `null` is the shipped default and the safe one: a range
    // with no egress gateway has no reviewed path off the cluster at all.
    egress: null,
  },
  guests: [
    guest("alpha-attacker", "secp-rng-alpha-attacker", 9101, "pve-node-1", "team-alpha", "secpv1a01",
      "BC:24:11:00:1A:01", "10.80.16.10", "10.80.16.10", "tmpl-kali-2026.1", 4, 8192, 60, "local-lvm", "qemu"),
    guest("alpha-web", "secp-rng-alpha-web", 9102, "pve-node-1", "team-alpha", "secpv1a02",
      "BC:24:11:00:1A:02", "10.80.17.20", "10.80.17.20", "tmpl-webbreach-2026.1", 2, 4096, 40, "local-lvm", "qemu"),
    guest("alpha-sensor", "secp-rng-alpha-sensor", 9103, "pve-node-2", "team-alpha", "secpv1a02",
      "BC:24:11:00:1A:03", "10.80.17.30", null, "tmpl-sensor-2026.1", 2, 2048, 20, "ceph-rbd", "lxc"),
    guest("bravo-attacker", "secp-rng-bravo-attacker", 9111, "pve-node-2", "team-bravo", "secpv1b01",
      "BC:24:11:00:1B:01", "10.80.18.10", "10.80.18.10", "tmpl-kali-2026.1", 4, 8192, 60, "local-lvm", "qemu"),
    guest("bravo-web", "secp-rng-bravo-web", 9112, "pve-node-2", "team-bravo", "secpv1b02",
      "BC:24:11:00:1B:02", "10.80.19.20", "10.80.19.20", "tmpl-webbreach-2026.1", 2, 4096, 40, "local-lvm", "qemu"),
    guest("bravo-sensor", "secp-rng-bravo-sensor", 9113, "pve-node-1", "team-bravo", "secpv1b02",
      "BC:24:11:00:1B:03", "10.80.19.30", null, "tmpl-sensor-2026.1", 2, 2048, 20, "ceph-rbd", "lxc"),
  ],
};

export const topologyFixture: OfflineRecord<CompiledTopology> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_api.range_providers.proxmox_network.compile_web_breach_lab",
  TOPOLOGY,
);

export const ipamPoolsFixture: OfflineRecord<IpamPools> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_api.range_providers.proxmox_ipam.IpamPools",
  {
    vmid_min: 9000,
    vmid_max: 9999,
    supernet: "10.80.0.0/12",
    segment_prefix: 24,
    vlan_min: 1000,
    vlan_max: 1999,
  },
);

export const allocationsFixture: OfflineRecord<ProxmoxAllocationOut[]> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_api.range_providers.proxmox_ipam.AllocationLedger",
  [
    // `label` and `team_ref` come from the endpoint projection (`allocation_rows`), not from the
    // ledger: `label` is the display name for the kind, and `team_ref` is the fourth element of
    // the allocation scope, null for range-wide allocations rather than an empty string.
    { kind: "zone_name", label: "SDN zone", purpose: "range zone", value: "secpz9a1", team_ref: null },
    { kind: "vlan_tag", label: "VLAN tag", purpose: "scoring segment", value: "1100", team_ref: null },
    { kind: "vlan_tag", label: "VLAN tag", purpose: "team-alpha attacker", value: "1101", team_ref: "team-alpha" },
    { kind: "vlan_tag", label: "VLAN tag", purpose: "team-alpha vulnerable", value: "1102", team_ref: "team-alpha" },
    { kind: "vlan_tag", label: "VLAN tag", purpose: "team-bravo attacker", value: "1103", team_ref: "team-bravo" },
    { kind: "vlan_tag", label: "VLAN tag", purpose: "team-bravo vulnerable", value: "1104", team_ref: "team-bravo" },
    { kind: "subnet", label: "Subnet", purpose: "team-alpha attacker", value: "10.80.16.0/24", team_ref: "team-alpha" },
    { kind: "subnet", label: "Subnet", purpose: "team-alpha vulnerable", value: "10.80.17.0/24", team_ref: "team-alpha" },
    { kind: "vmid", label: "VM id", purpose: "alpha-attacker", value: "9101", team_ref: "team-alpha" },
    { kind: "vmid", label: "VM id", purpose: "alpha-web", value: "9102", team_ref: "team-alpha" },
    { kind: "lxc_id", label: "Container id", purpose: "alpha-sensor", value: "9103", team_ref: "team-alpha" },
    { kind: "mac", label: "MAC address", purpose: "alpha-attacker nic0", value: "BC:24:11:00:1A:01", team_ref: "team-alpha" },
    {
      kind: "remote_state_key",
      label: "Remote state key",
      // The KEY, never the credential that opens it — see `allocation_rows`.
      purpose: "opentofu state",
      value: `secp/${RANGE}/gen-${GENERATION}`,
      team_ref: null,
    },
  ],
);

export const isolationFixture: OfflineRecord<IsolationFindingOut[]> = offlineFixture(
  "A worked example of what GET /api/v1/ranges/{range_id}/proxmox/plan returns in its `isolation` member. These are properties of the PLAN, checked by the compiler — not observations of a running cluster.",
  "secp_api.range_providers.proxmox_network.verify_isolation",
  [
    { property: "cross_team_blocked", holds: true, detail: "No rule permits team-alpha segments to reach team-bravo segments." },
    { property: "management_plane_unreachable", holds: true, detail: "10.20.0.0/24 is dropped outbound from every team segment." },
    { property: "control_plane_unreachable", holds: true, detail: "No rule permits a guest segment to reach the control plane." },
    { property: "no_default_public_route", holds: true, detail: "No egress gateway is compiled and no default ACCEPT exists." },
    { property: "default_deny_present", holds: true, detail: "Each security group ends in an unconditional outbound DROP." },
    { property: "scoring_reachable", holds: true, detail: "tcp/443 to 10.80.15.0/24 is permitted from each attacker segment." },
  ],
);

export const reviewedImagesFixture: OfflineRecord<ReviewedGuestImage[]> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_api.range_providers.proxmox_workload.ReviewedGuestImage",
  [
    {
      workload_key: "attacker-kali",
      role: "attacker",
      template_ref: "tmpl-kali-2026.1",
      workload_version: "2026.1.0",
      image_digest: fakeHash("1"),
      approval_reference: "SECP-IMG-2026-014",
      guest_kind: "qemu",
      clone_strategy: "full",
      service_port: 22,
    },
    {
      workload_key: "web-breach-target",
      role: "target",
      template_ref: "tmpl-webbreach-2026.1",
      workload_version: "2026.1.3",
      image_digest: fakeHash("2"),
      approval_reference: "SECP-IMG-2026-021",
      guest_kind: "qemu",
      clone_strategy: "full",
      service_port: 80,
    },
    {
      workload_key: "segment-sensor",
      role: "sensor",
      template_ref: "tmpl-sensor-2026.1",
      workload_version: "2026.1.0",
      image_digest: fakeHash("3"),
      approval_reference: "SECP-IMG-2026-009",
      guest_kind: "lxc",
      clone_strategy: "linked",
      service_port: 514,
    },
  ],
);

export const readinessFixture: OfflineRecord<ReadinessFindingOut[]> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_api.range_providers.proxmox_workload.assess_competition_readiness",
  [
    { requirement: "two_teams_present", met: true, detail: "team-alpha and team-bravo." },
    { requirement: "attacker_per_team", met: true, detail: "One attacker guest per team." },
    { requirement: "targets_per_team", met: true, detail: "One vulnerable target per team." },
    { requirement: "challenges_covered", met: true, detail: "Six challenges map to compiled workloads." },
    { requirement: "scoring_reachable_by_plan", met: true, detail: "Scoring segment reachable on tcp/443 from each attacker segment." },
    { requirement: "flags_delivered_out_of_band", met: true, detail: "No flag value appears in the desired state or any plan document." },
    { requirement: "bootstrap_bounded_and_observable", met: true, detail: "Bootstrap deadline 900s; each guest reports to the scoring address." },
    { requirement: "workload_versions_pinned", met: true, detail: "Every image is pinned by digest and approval reference." },
  ],
);

// ------------------------------------------------------------------------------- plan / apply

const APPLY_CHANGE_SET_HASH = fakeHash("a");

export const planDocumentFixture: OfflineRecord<PlanDocument> = offlineFixture(
  "No endpoint serves an OpenTofu plan document: it is built and held inside the privileged worker. The API publishes the DESIRED STATE document it compiled (`secp-proxmox/desired-state-document/v1`), which is a different document with a different version string.",
  "secp_worker.provisioning.plan_document.build_plan_document",
  {
    version: PLAN_DOCUMENT_VERSION,
    execution_status: EXECUTION_STATUS_NOT_APPLIED,
    change_set_hash: APPLY_CHANGE_SET_HASH,
    desired_state_hash: fakeHash("b"),
    plan_document_hash: fakeHash("d"),
    create_addresses: [
      "proxmox_virtual_environment_sdn_zone.range",
      "proxmox_virtual_environment_sdn_vnet.scoring",
      "proxmox_virtual_environment_sdn_vnet.alpha_attacker",
      "proxmox_virtual_environment_sdn_vnet.alpha_vulnerable",
      "proxmox_virtual_environment_sdn_vnet.bravo_attacker",
      "proxmox_virtual_environment_sdn_vnet.bravo_vulnerable",
      "proxmox_virtual_environment_firewall_security_group.alpha",
      "proxmox_virtual_environment_firewall_security_group.bravo",
      "proxmox_virtual_environment_firewall_ipset.management",
      "proxmox_virtual_environment_firewall_ipset.scoring",
      "proxmox_virtual_environment_vm.alpha_attacker",
      "proxmox_virtual_environment_vm.alpha_web",
      "proxmox_virtual_environment_container.alpha_sensor",
      "proxmox_virtual_environment_vm.bravo_attacker",
      "proxmox_virtual_environment_vm.bravo_web",
      "proxmox_virtual_environment_container.bravo_sensor",
    ],
    update_addresses: [],
    delete_addresses: [],
    generated_at: "2026-08-05T09:14:22Z",
  },
);

export const planApprovalStateFixture: OfflineRecord<PlanApprovalState> = offlineFixture(
  "An operator projection, not a server enum. The API records approvals as `ApprovalOut` and publishes plan state as `PlanState`; this is how a review screen names the same facts.",
  "secp_worker.provisioning.proxmox_apply_gate.ApprovedPlanBinding",
  "draft",
);

export const applyAuthorizationStateFixture: OfflineRecord<ApplyAuthorizationState> = offlineFixture(
  "An operator projection over `AuthorizationState`. The apply GATE decision itself is taken on the worker at claim time and has no endpoint — the API publishes only what it recorded about the authorization.",
  "secp_worker.provisioning.proxmox_apply_gate.evaluate_apply_gate",
  "plan_awaiting_review",
);

/** Present so the authorized shape is reviewable. It is NOT the state the fixture screen shows. */
export const applyAuthorizationFixture: OfflineRecord<ApplyAuthorization> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_apply_gate.ApplyAuthorization",
  {
    change_set_hash: APPLY_CHANGE_SET_HASH,
    desired_state_hash: fakeHash("b"),
    ownership_scope: [ORG, TARGET, RANGE, GENERATION],
    checks_passed: [
      "prepared_plan_present",
      "change_set_hash_matches",
      "desired_state_matches",
      "allocations_match",
      "ownership_scope_matches",
      "worker_identity_matches",
      "worker_release_matches",
      "target_matches",
    ],
  },
);

export const authoritativeStateFixture: OfflineRecord<AuthoritativeState> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_apply_gate.AuthoritativeState",
  {
    onboarding_current: true,
    eligibility_passing: true,
    discovery_fresh: true,
    reservations_persisted: true,
    // Deliberately left unstated in the example: the gate treats it as unsatisfied and refuses, and
    // the surface must show "not stated" rather than "no" — they are different facts.
    remote_state_lock_held: null,
    credential_resolved: true,
  },
);

export const workerIdentityFixture: OfflineRecord<WorkerIdentity> = offlineFixture(
  "The enrolled worker list is live; the identity the APPLY GATE binds a plan to is not served anywhere.",
  "secp_worker.provisioning.proxmox_apply_gate.WorkerIdentity",
  {
    worker_id: "wkr-pve-lab-01",
    role: INFRASTRUCTURE_OPERATOR_ROLE,
    release: "2026.8.0",
    queue: "controlled-live",
  },
);

// ------------------------------------------------------------------------------ verification

export const verificationFixture: OfflineRecord<VerificationReport> = offlineFixture(
  "The report shape the worker records. The API republishes its findings through `ProxmoxVerificationOut.infrastructure_checks` / `.isolation_checks`, which OpenAPI types as opaque objects — so this transcription is what the (observed, ok) pair is read against.",
  "secp_worker.provisioning.proxmox_verification.verify_deployment",
  {
    // The example deliberately shows the amber outcome. It is the one a renderer is most likely to
    // collapse into success or failure, so it is the one worth having on screen by default.
    outcome: "recovery_required",
    findings: [
      { check: "guest_inventory", observed: true, ok: true, detail: "6 of 6 guests present at the allocated VMIDs." },
      { check: "guest_names", observed: true, ok: true, detail: "Names match the desired state." },
      { check: "node_placement", observed: true, ok: true, detail: "Placement matches: 3 on pve-node-1, 3 on pve-node-2." },
      { check: "disks_and_storage", observed: true, ok: true, detail: "Disk slots and storage ids match." },
      { check: "nics_and_macs", observed: true, ok: true, detail: "6 NICs, MACs match the allocation ledger." },
      { check: "network_objects", observed: true, ok: true, detail: "Zone and 5 VNets present with the planned VLAN tags." },
      { check: "firewall_objects", observed: true, ok: true, detail: "2 security groups and 2 IP sets present." },
      { check: "ownership_tags", observed: true, ok: true, detail: "Every object carries the range ownership stamp." },
      { check: "power_state", observed: true, ok: true, detail: "All guests running." },
      { check: "guest_readiness", observed: true, ok: true, detail: "All guests reported bootstrap completion within the deadline." },
      { check: "required_reachability", observed: true, ok: true, detail: "Scoring reachable from both attacker segments." },
      // The four isolation checks could not be run: the segment prober was unreachable. That is
      // precisely NOT a finding that isolation failed.
      { check: "cross_team_denial", observed: false, ok: false, detail: "Segment prober unreachable — denial not observed." },
      { check: "management_denial", observed: false, ok: false, detail: "Segment prober unreachable — denial not observed." },
      { check: "protected_denial", observed: false, ok: false, detail: "Segment prober unreachable — denial not observed." },
      { check: "external_denial", observed: false, ok: false, detail: "Segment prober unreachable — denial not observed." },
      { check: "state_agreement", observed: true, ok: true, detail: "OpenTofu state addresses match observed objects." },
    ],
  },
);

export const reconcileFixture: OfflineRecord<ReconcileDecision> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_reconcile.decide_reconciliation",
  {
    action: "halt",
    outcome: "recovery_required",
    reason: "proxmox.reconcile.provider_unobservable",
    detail: "The provider could not be observed, so no reconciliation decision can be justified. A human must look before anything else runs.",
    create_vmids: [],
  },
);

export const resetPlanFixture: OfflineRecord<ResetPlan> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_reset.plan_reset",
  {
    range_id: RANGE,
    operation_generation: OPERATION_GENERATION + 1,
    topology_fingerprint: fakeHash("e"),
    recreated_guest_refs: ["alpha-web", "bravo-web"],
    actions: [
      { subject: "range_identity", disposition: "preserved", detail: "Range id, ownership and generation unchanged." },
      { subject: "sdn_zone", disposition: "preserved", detail: "Zone secpz9a1 is not recreated." },
      { subject: "vnets", disposition: "preserved", detail: "All 5 VNets preserved." },
      { subject: "subnets_and_vlans", disposition: "preserved", detail: "Allocations retained; no renumbering." },
      { subject: "firewall_objects", disposition: "preserved", detail: "Security groups and IP sets preserved." },
      { subject: "allocation_ledger", disposition: "preserved", detail: "Sealed ledger reused; operation generation advanced." },
      { subject: "guests", disposition: "recreated", detail: "Target guests recreated from the pinned templates." },
      { subject: "challenge_state", disposition: "cleared", detail: "Per-challenge solve state cleared." },
      { subject: "team_membership", disposition: "preserved", detail: "Teams and rosters survive a reset." },
      { subject: "scores", disposition: "cleared", detail: "Scores cleared server-side. The browser never adjusts a total." },
    ],
  },
);

// ------------------------------------------------------------------------------ destroy side

/**
 * A DIFFERENT change-set hash from the apply plan, and a deletion-set hash the apply plan does not
 * have at all. `assertSeparateAuthorizations` checks the first of those at render time.
 */
const DESTROY_CHANGE_SET_HASH = fakeHash("7");
const DELETION_SET_HASH = fakeHash("8");

export const destroyPlanFixture: OfflineRecord<PlanDocument> = offlineFixture(
  "No endpoint serves a worker destroy plan document. The API publishes the destroy hash, the deletion set and the approval through /proxmox/destroy-plan; this is the worker-side document behind them.",
  "secp_worker.provisioning.plan_document.build_plan_document (destroy)",
  {
    version: PLAN_DOCUMENT_VERSION,
    execution_status: EXECUTION_STATUS_NOT_APPLIED,
    change_set_hash: DESTROY_CHANGE_SET_HASH,
    desired_state_hash: fakeHash("b"),
    plan_document_hash: fakeHash("9"),
    create_addresses: [],
    update_addresses: [],
    delete_addresses: [
      "proxmox_virtual_environment_vm.alpha_attacker",
      "proxmox_virtual_environment_vm.alpha_web",
      "proxmox_virtual_environment_container.alpha_sensor",
      "proxmox_virtual_environment_vm.bravo_attacker",
      "proxmox_virtual_environment_vm.bravo_web",
      "proxmox_virtual_environment_container.bravo_sensor",
      "proxmox_virtual_environment_firewall_security_group.alpha",
      "proxmox_virtual_environment_firewall_security_group.bravo",
      "proxmox_virtual_environment_firewall_ipset.management",
      "proxmox_virtual_environment_firewall_ipset.scoring",
      "proxmox_virtual_environment_sdn_vnet.scoring",
      "proxmox_virtual_environment_sdn_vnet.alpha_attacker",
      "proxmox_virtual_environment_sdn_vnet.alpha_vulnerable",
      "proxmox_virtual_environment_sdn_vnet.bravo_attacker",
      "proxmox_virtual_environment_sdn_vnet.bravo_vulnerable",
      "proxmox_virtual_environment_sdn_zone.range",
    ],
    generated_at: "2026-08-05T14:02:51Z",
  },
);

export const deletionSetHashFixture: OfflineRecord<string> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_destroy_gate.deletion_set_hash",
  DELETION_SET_HASH,
);

export const destroyApprovalFixture: OfflineRecord<DestroyApproval> = offlineFixture(
  "The worker-side approval the destroy gate consumes. The API records its own `ApprovalOut` with a four-member `operation_kind`; this is the gate’s marker, kept so the operation-kind binding stays reviewable on both sides.",
  "secp_worker.provisioning.proxmox_destroy_gate.DestroyApproval",
  {
    operation_kind: DESTROY_OPERATION_KIND,
    change_set_hash: DESTROY_CHANGE_SET_HASH,
    deletion_set_hash: DELETION_SET_HASH,
    plan_document_hash: fakeHash("9"),
    ownership_scope: [ORG, TARGET, RANGE, GENERATION],
    target_id: TARGET,
    cluster_fingerprint: fakeHash("c"),
    worker_id: "wkr-pve-lab-01",
    worker_release: "2026.8.0",
    approval_id: "apr-destroy-4c19",
  },
);

export const destroyAuthorizationStateFixture: OfflineRecord<DestroyAuthorizationState> =
  offlineFixture(
    "An operator projection over `AuthorizationState` for destroy. The destroy GATE decision is taken on the worker at claim time and has no endpoint of its own.",
    "secp_worker.provisioning.proxmox_destroy_gate.evaluate_destroy_gate",
    "not_requested",
  );

export const destroyPreconditionsFixture: OfflineRecord<DestroyPreconditions> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_destroy_gate.DestroyPreconditions",
  {
    ownership_verified: true,
    discovery_fresh: true,
    remote_state_lock_held: null,
    credential_resolved: true,
    approval_already_consumed: false,
  },
);

export const deletionSetFixture: OfflineRecord<DeletionSet> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_residue.bound_deletion_set",
  {
    deletable: [
      { residue_class: "qemu_vm", identifier: "9101", address: "proxmox_virtual_environment_vm.alpha_attacker" },
      { residue_class: "qemu_vm", identifier: "9102", address: "proxmox_virtual_environment_vm.alpha_web" },
      { residue_class: "lxc_container", identifier: "9103", address: "proxmox_virtual_environment_container.alpha_sensor" },
      { residue_class: "qemu_vm", identifier: "9111", address: "proxmox_virtual_environment_vm.bravo_attacker" },
      { residue_class: "qemu_vm", identifier: "9112", address: "proxmox_virtual_environment_vm.bravo_web" },
      { residue_class: "lxc_container", identifier: "9113", address: "proxmox_virtual_environment_container.bravo_sensor" },
      { residue_class: "sdn_zone", identifier: "secpz9a1", address: "proxmox_virtual_environment_sdn_zone.range" },
      { residue_class: "vnet", identifier: "secpv1s00", address: "proxmox_virtual_environment_sdn_vnet.scoring" },
      { residue_class: "firewall_group", identifier: "secpg1a01", address: null },
      { residue_class: "ip_set", identifier: "secpi1m00", address: null },
      { residue_class: "vmid_reservation", identifier: "9101", address: null },
      { residue_class: "mac_reservation", identifier: "BC:24:11:00:1A:01", address: null },
      { residue_class: "remote_state_object", identifier: `secp/${RANGE}/gen-${GENERATION}`, address: null },
    ],
    protected: [
      {
        resource: { residue_class: "vnet", identifier: "vmbr0-legacy", address: null },
        provenance: "untagged",
        detail: "No SECP ownership tag. Not created by this control plane and never deleted by it.",
      },
      {
        resource: { residue_class: "qemu_vm", identifier: "8004", address: null },
        provenance: "secp_foreign_scope",
        detail: "Tagged for range rng-other-02. Out of this range's ownership scope.",
      },
      {
        resource: { residue_class: "sdn_zone", identifier: "zone-unreadable", address: null },
        provenance: "unreadable",
        detail: "Tags could not be read. An object that cannot be classified is never deleted.",
      },
    ],
    already_absent: [
      { residue_class: "cloud_init_snippet", identifier: "secp-ci-alpha-web", address: null },
    ],
    undetermined: [
      { residue_class: "disk_volume", identifier: "ceph-rbd:vm-9103-disk-0", address: null },
    ],
  },
);

export const absenceFindingsFixture: OfflineRecord<AbsenceFinding[]> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_residue.verify_absence",
  [
    { resource: { residue_class: "qemu_vm", identifier: "9101", address: null }, outcome: "removed", probe_healthy: true, detail: "Confirmed absent by a probe that was itself working." },
    { resource: { residue_class: "qemu_vm", identifier: "9102", address: null }, outcome: "removed", probe_healthy: true, detail: "Confirmed absent." },
    { resource: { residue_class: "lxc_container", identifier: "9103", address: null }, outcome: "removed", probe_healthy: true, detail: "Confirmed absent." },
    { resource: { residue_class: "qemu_vm", identifier: "9111", address: null }, outcome: "removed", probe_healthy: true, detail: "Confirmed absent." },
    { resource: { residue_class: "qemu_vm", identifier: "9112", address: null }, outcome: "present", probe_healthy: true, detail: "Still present at VMID 9112. Deletion did not complete." },
    { resource: { residue_class: "lxc_container", identifier: "9113", address: null }, outcome: "unproven", probe_healthy: false, detail: "The provider API was unreachable, so removal and the existence check failed for the same reason. Absence is NOT proved." },
    { resource: { residue_class: "disk_volume", identifier: "ceph-rbd:vm-9103-disk-0", address: null }, outcome: "unproven", probe_healthy: false, detail: "Storage listing unavailable. Nothing proved either way." },
    { resource: { residue_class: "remote_state_object", identifier: `secp/${RANGE}/gen-${GENERATION}`, address: null }, outcome: "removed", probe_healthy: true, detail: "Remote state key absent." },
  ],
);

export const zeroResidueProofFixture: OfflineRecord<ZeroResidueProof> = offlineFixture(
  OFFLINE_EXAMPLE,
  "secp_worker.provisioning.proxmox_residue.zero_residue_proof",
  {
    verdict: "unproven",
    expected_count: 8,
    confirmed_absent: 5,
    still_present: 1,
    unproven: 2,
    protected: ["vmbr0-legacy", "8004", "zone-unreadable"],
    uncovered: ["firewall_alias", "bootstrap_object"],
    released_reservations: 5,
    retained_reservations: 3,
  },
);
