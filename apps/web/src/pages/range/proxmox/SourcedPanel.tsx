import type { ReactNode } from "react";

import { CyberCard, SafetyNotice } from "../../../components/ui";
import {
  LIVE_DATA_EXPLANATION,
  OFFLINE_DATA_EXPLANATION,
  OFFLINE_DATA_LABEL,
  type Provenance,
  type Sourced,
} from "./provenance";

/**
 * The only way a Proxmox panel renders.
 *
 * The banner is DERIVED from the record's provenance, not passed alongside it. There is therefore
 * no call site that can render fixture data and forget the label: to render the value at all you
 * hand over the `Sourced<T>`, and the wrapper reads the discriminant itself.
 *
 * `render` takes the unwrapped value so panel bodies stay ordinary, but it is only reachable
 * through this component — `provenance.ts` deliberately exports no standalone unwrap.
 */
export interface SourcedPanelProps<T> {
  heading: ReactNode;
  headingLevel?: 2 | 3 | 4;
  record: Sourced<T>;
  /** Optional lead paragraph, rendered under the banner and above the body. */
  intro?: ReactNode;
  render: (value: T) => ReactNode;
}

export function SourcedPanel<T>({
  heading,
  headingLevel = 2,
  record,
  intro,
  render,
}: SourcedPanelProps<T>) {
  const offline = record.provenance.kind === "offline-fixture";
  return (
    <CyberCard
      heading={heading}
      headingLevel={headingLevel}
      className={offline ? "pmx-panel pmx-panel--offline" : "pmx-panel pmx-panel--live"}
      data-provenance={record.provenance.kind}
    >
      <ProvenanceBanner provenance={record.provenance} />
      {intro !== undefined && <p className="rng-sub">{intro}</p>}
      {render(record.value)}
    </CyberCard>
  );
}

/**
 * The disclosure itself.
 *
 * Offline uses `role="note"` with `tone="warn"`: it is a standing property of the panel, not an
 * event, and amber rather than red because nothing has gone wrong — there is simply no endpoint.
 * The live variant is a quiet one-liner naming the exact path, so an operator can tell the two
 * apart without reading the copy: a labelled panel and an endpoint-stamped panel never look alike.
 */
export function ProvenanceBanner({ provenance }: { provenance: Provenance }) {
  if (provenance.kind === "live") {
    return (
      <p className="pmx-live-source">
        <span className="pmx-live-dot" aria-hidden="true" />
        <span className="pmx-source-label">Live</span>{" "}
        <span className="muted">{LIVE_DATA_EXPLANATION}</span>{" "}
        <code className="mono">{provenance.endpoint}</code>
      </p>
    );
  }
  return (
    <SafetyNotice role="note" tone="warn">
      <strong className="pmx-offline-label">{OFFLINE_DATA_LABEL}</strong>
      <span className="pmx-offline-body"> {OFFLINE_DATA_EXPLANATION}</span>
      <span className="pmx-offline-body"> {provenance.reason}</span>
      <span className="pmx-offline-model muted">
        {" "}
        Shape taken from <code className="mono">{provenance.modelledOn}</code>.
      </span>
    </SafetyNotice>
  );
}

/**
 * Compact inline marker for a single value inside an otherwise live panel — a placement column on
 * a live worker row, say. Same word as the banner, so the two are recognisably the same claim.
 */
export function OfflineChip({ title }: { title?: string }) {
  return (
    <span className="pmx-offline-chip" title={title ?? OFFLINE_DATA_EXPLANATION}>
      {OFFLINE_DATA_LABEL}
    </span>
  );
}
