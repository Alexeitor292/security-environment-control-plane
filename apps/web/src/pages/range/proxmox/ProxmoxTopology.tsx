import "../range.css";
import "./proxmox.css";

import { CyberCard, CyberTable, HashChip, KeyValueList, MetricTile, SafetyNotice, StatusBadge } from "../../../components/ui";
import { ProxmoxSection } from "./ProxmoxSection";
import { SourcedPanel } from "./SourcedPanel";
import {
  allocationsFixture,
  ipamPoolsFixture,
  isolationFixture,
  reviewedImagesFixture,
  topologyFixture,
} from "./proxmox-fixtures";
import {
  OWNERSHIP_NOTE,
  PROBE_ADDRESS_NOTE,
  guestRows,
  humanize,
  isolationHolds,
  ownershipLine,
  sharedSegments,
  teamTopology,
} from "./proxmox-view";

/**
 * Topology and network design — the compiled desired state.
 *
 * ENTIRELY OFFLINE. `compile_web_breach_lab` and the allocation ledger are library code in
 * `secp_api.range_providers`, imported by tests and by the worker and by no router. Nothing on
 * this page was read from a cluster and every panel says so.
 *
 * What it is for: the compiled plan is where segmentation is decided, and segmentation is the
 * property an operator most needs to be able to read before anything runs. The worked example
 * shows the shape that decision takes.
 */
export function ProxmoxTopology() {
  const topology = topologyFixture.value;
  const teams = teamTopology(topology.network, topology.guests);
  const shared = sharedSegments(topology.network);
  const guests = guestRows(topology.guests);
  const isolation = isolationFixture.value;
  const allIsolationHolds = isolationHolds(isolation);
  const totalMemoryMb = guests.reduce((s, g) => s + g.memoryMb, 0);
  const totalDiskGb = guests.reduce((s, g) => s + g.totalDiskGb, 0);
  const totalCores = guests.reduce((s, g) => s + g.cpuCores, 0);

  return (
    <div className="rng">
      <ProxmoxSection>
      <div className="rng-grid">
        <MetricTile label="Guests" value={guests.length} detail={`${totalCores} vCPU · ${Math.round(totalMemoryMb / 1024)} GiB · ${totalDiskGb} GB disk`} />
        <MetricTile label="Segments" value={topology.network.vnets.length} detail={`1 zone · ${teams.length} team${teams.length === 1 ? "" : "s"} · ${shared.length} shared`} />
        <MetricTile
          label="Plan isolation"
          value={allIsolationHolds ? "All properties hold" : "Not all hold"}
          detail="A property of the compiled plan, not an observation of a cluster"
          tone={allIsolationHolds ? "ok" : "danger"}
        />
      </div>

      <SourcedPanel
        heading="Target and ownership"
        record={topologyFixture}
        intro={OWNERSHIP_NOTE}
        render={(t) => (
          <KeyValueList
            items={[
              { key: "Cluster", value: t.target.cluster_name },
              { key: "Target id", value: t.target.target_id, mono: true },
              { key: "Cluster fingerprint", value: <HashChip value={t.target.cluster_fingerprint} /> },
              { key: "Management CIDRs", value: t.target.management_cidrs.join(", "), mono: true },
              { key: "Management bridges", value: t.target.management_bridges.join(", "), mono: true },
              { key: "Ownership", value: ownershipLine(t.ownership), mono: true },
              { key: "SDN zone", value: `${t.network.zone.name} on ${t.network.zone.bridge}`, mono: true },
              { key: "Zone nodes", value: t.network.zone.nodes.join(", "), mono: true },
              { key: "Zone MTU", value: t.network.zone.mtu === null ? "default" : String(t.network.zone.mtu) },
              {
                key: "Egress gateway",
                value:
                  t.network.egress === null
                    ? "none — no reviewed path off the cluster"
                    : `${t.network.egress.vnet_name} (approval ${t.network.egress.approval_reference})`,
              },
            ]}
          />
        )}
      />

      <SourcedPanel
        heading="Team topology"
        record={topologyFixture}
        intro="Each team gets its own segments and its own guests. A team ref on an object is part of its ownership stamp, which is what keeps one team's teardown from touching another's."
        render={() => (
          <>
            {teams.map((team) => (
              <CyberCard key={team.teamRef} heading={team.teamRef} headingLevel={3} surface="well">
                <CyberTable
                  label={`${team.teamRef} segments`}
                  head={["VNet", "Role", "VLAN", "CIDR", "Gateway", "Security group"]}
                  caption={`${team.segments.length} segment${team.segments.length === 1 ? "" : "s"} · ${team.guests.length} guest${team.guests.length === 1 ? "" : "s"}`}
                >
                  {team.segments.map((s) => (
                    <tr key={s.vnet}>
                      <td className="mono">
                        {s.vnet}
                        {s.alias !== "" && <span className="muted"> {s.alias}</span>}
                      </td>
                      <td>
                        <span className="badge accent">{s.role}</span>
                      </td>
                      <td className="muted mono">{s.vlanTag}</td>
                      <td className="mono">{s.cidr}</td>
                      <td className="muted mono">{s.gateway}</td>
                      <td className="muted mono">{s.securityGroup ?? "—"}</td>
                    </tr>
                  ))}
                </CyberTable>
              </CyberCard>
            ))}

            <CyberCard heading="Shared segments" headingLevel={3} surface="well">
              <CyberTable
                label="Shared segments"
                head={["VNet", "Role", "VLAN", "CIDR", "Gateway", "Routed"]}
                caption="Segments with no team ref. The scoring segment is shared by design; it is reachable from each team and does not join them to one another."
              >
                {shared.map((s) => (
                  <tr key={s.vnet}>
                    <td className="mono">{s.vnet}</td>
                    <td>
                      <span className="badge accent">{s.role}</span>
                    </td>
                    <td className="muted mono">{s.vlanTag}</td>
                    <td className="mono">{s.cidr}</td>
                    <td className="muted mono">{s.gateway}</td>
                    <td className="muted">{s.routed ? "routed" : "isolated"}</td>
                  </tr>
                ))}
              </CyberTable>
            </CyberCard>
          </>
        )}
      />

      <SourcedPanel
        heading="Guests"
        record={topologyFixture}
        intro={PROBE_ADDRESS_NOTE}
        render={() => (
          <CyberTable
            label="Planned guests"
            head={["Guest", "Kind", "VMID", "Node", "CPU / memory", "Disks", "Template", "NIC", "Addresses"]}
            caption={`${guests.length} guests · every one carries the range ownership stamp shown in the row title`}
          >
            {guests.map((g) => (
              <tr key={g.guestRef} title={g.ownershipLine}>
                <td>
                  {g.name}
                  <div className="muted pmx-detail mono">{g.guestRef}</div>
                </td>
                <td>
                  <span className="badge accent">{g.kind}</span>
                </td>
                <td className="mono">{g.vmid}</td>
                <td className="muted mono">{g.node}</td>
                <td className="muted mono">
                  {g.cpuCores} vCPU / {Math.round(g.memoryMb / 1024)} GiB
                </td>
                <td className="muted mono">
                  {g.disks.map((d) => (
                    <div key={d}>{d}</div>
                  ))}
                </td>
                <td className="muted mono">
                  {g.template}
                  <div className="pmx-detail">{g.cloneStrategy} clone</div>
                </td>
                <td className="muted mono">
                  {g.vnets.join(", ")}
                  <div className="pmx-detail">{g.macs.join(", ")}</div>
                </td>
                <td className="mono">
                  <div>published {g.publishedAddress}</div>
                  <div className={g.probeAddress === null ? "pmx-unproven" : "muted"}>
                    {g.probeAddress === null ? "probe: none reachable" : `probe ${g.probeAddress}`}
                  </div>
                </td>
              </tr>
            ))}
          </CyberTable>
        )}
      />

      <SourcedPanel
        heading="Source templates"
        record={reviewedImagesFixture}
        intro="Every guest is cloned from a reviewed template pinned by digest and approval reference. An unpinned image is refused by the readiness assessment (workload_versions_pinned)."
        render={(images) => (
          <CyberTable
            label="Reviewed guest images"
            head={["Workload", "Role", "Template", "Version", "Digest", "Approval", "Clone"]}
            caption={`${images.length} reviewed images`}
          >
            {images.map((i) => (
              <tr key={i.workload_key}>
                <td className="mono">{i.workload_key}</td>
                <td>
                  <span className="badge accent">{i.role}</span>
                </td>
                <td className="muted mono">{i.template_ref}</td>
                <td className="muted mono">{i.workload_version}</td>
                <td>
                  <HashChip value={i.image_digest} />
                </td>
                <td className="muted mono">{i.approval_reference}</td>
                <td className="muted">
                  {i.clone_strategy} · {i.guest_kind}
                </td>
              </tr>
            ))}
          </CyberTable>
        )}
      />

      <SourcedPanel
        heading="Firewall intent"
        record={topologyFixture}
        intro="The compiled rules, in evaluation order. This is INTENT: what the plan says should be enforced. Whether it is enforced is a verification question, answered on the Verification tab and only where a probe actually ran."
        render={(t) => (
          <>
            {t.network.security_groups.map((group) => (
              <CyberCard key={group.name} heading={group.name} headingLevel={3} surface="well">
                <p className="rng-sub">{group.comment}</p>
                <CyberTable
                  label={`${group.name} rules`}
                  head={["#", "Direction", "Verdict", "Source", "Destination", "Proto", "Port", "Comment"]}
                  caption={`${group.rules.length} rules · the final unconditional DROP is the default-deny`}
                >
                  {group.rules.map((r) => (
                    <tr key={r.position}>
                      <td className="muted mono">{r.position}</td>
                      <td className="muted mono">{r.direction}</td>
                      <td>
                        <span className={`badge ${r.verdict === "ACCEPT" ? "ok" : "danger"}`}>
                          {r.verdict}
                        </span>
                      </td>
                      <td className="muted mono">{r.source ?? "any"}</td>
                      <td className="muted mono">{r.dest ?? "any"}</td>
                      <td className="muted mono">{r.proto ?? "any"}</td>
                      <td className="muted mono">{r.dport ?? "any"}</td>
                      <td className="muted">{r.comment}</td>
                    </tr>
                  ))}
                </CyberTable>
              </CyberCard>
            ))}

            <CyberCard heading="IP sets" headingLevel={3} surface="well">
              <CyberTable label="IP sets" head={["Name", "CIDRs", "Comment"]}>
                {t.network.ip_sets.map((s) => (
                  <tr key={s.name}>
                    <td className="mono">{s.name}</td>
                    <td className="mono">{s.cidrs.join(", ")}</td>
                    <td className="muted">{s.comment}</td>
                  </tr>
                ))}
              </CyberTable>
            </CyberCard>
          </>
        )}
      />

      <SourcedPanel
        heading="Isolation properties of the compiled plan"
        record={isolationFixture}
        intro="These are checked against the compiled rules by the compiler itself. A property that holds here means the PLAN provides it. It does not mean the cluster enforces it — that claim can only come from an observation."
        render={(findings) => (
          <CyberTable
            label="Isolation properties"
            head={["Property", "Holds in plan", "Detail"]}
            caption="Compiler findings. Enforcement is verified separately, and only where a probe ran."
          >
            {findings.map((f) => (
              <tr key={f.prop}>
                <td className="mono">{humanize(f.prop)}</td>
                <td>
                  <StatusBadge state={f.holds ? "verified" : "failed"} domain="range-operation" />
                </td>
                <td className="muted">{f.detail}</td>
              </tr>
            ))}
          </CyberTable>
        )}
      />

      <SourcedPanel
        heading="Allocations"
        record={allocationsFixture}
        intro="Every identifier the range occupies is drawn from a bounded pool and recorded in the allocation ledger. Teardown releases an allocation only when the object that held it is proved gone."
        render={(allocations) => (
          <>
            <KeyValueList
              items={[
                { key: "VMID pool", value: `${ipamPoolsFixture.value.vmid_min}–${ipamPoolsFixture.value.vmid_max}`, mono: true },
                { key: "Supernet", value: ipamPoolsFixture.value.supernet, mono: true },
                { key: "Segment prefix", value: `/${ipamPoolsFixture.value.segment_prefix}`, mono: true },
                { key: "VLAN pool", value: `${ipamPoolsFixture.value.vlan_min}–${ipamPoolsFixture.value.vlan_max}`, mono: true },
              ]}
            />
            <CyberTable
              label="Allocation ledger"
              head={["Kind", "Purpose", "Value"]}
              caption={`${allocations.length} allocations shown`}
            >
              {allocations.map((a) => (
                <tr key={`${a.kind}:${a.value}`}>
                  <td className="muted mono">{humanize(a.kind)}</td>
                  <td className="muted">{a.purpose}</td>
                  <td className="mono">{a.value}</td>
                </tr>
              ))}
            </CyberTable>
          </>
        )}
      />

      <SafetyNotice role="note" tone="info">
        {OWNERSHIP_NOTE}
      </SafetyNotice>
      </ProxmoxSection>
    </div>
  );
}
