import "./range.css";

import { CyberCard, EmptyState, SafetyNotice } from "../../components/ui";
import { MISSING_COMPETITION_ENDPOINTS } from "./scoreboard-view";

export interface PendingContractPanelProps {
  heading: string;
  title: string;
  body: string;
  /** The specific endpoints this surface needs. Defaults to the competition set. */
  endpoints?: readonly string[];
}

/**
 * The honest empty state for a surface whose backend does not exist yet.
 *
 * It names the exact endpoints that are missing rather than saying "coming soon", because an
 * operator (or a reviewer) looking at this page needs to be able to tell the difference between
 * "the server returned nothing" and "there is no server route to call". Those are very different
 * failures and only one of them is a bug.
 *
 * This deliberately renders NO sample standings, NO placeholder teams and NO zeroed score. A
 * scoreboard showing 0 for every team is a claim about the competition; a page that says the
 * scoreboard endpoint does not exist is a fact about the build.
 */
export function PendingContractPanel({
  heading,
  title,
  body,
  endpoints = MISSING_COMPETITION_ENDPOINTS,
}: PendingContractPanelProps) {
  return (
    <CyberCard heading={heading} headingLevel={2}>
      <SafetyNotice role="note" tone="warn">
        This surface is not wired to a backend. Nothing below is simulated, sampled or placeholder
        data — there is simply no data, because the API exposes no route to ask.
      </SafetyNotice>

      <EmptyState title={title}>
        <p>{body}</p>
        <p>Required API surface, not present in this build:</p>
        <ul className="rng-pending-list">
          {endpoints.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      </EmptyState>
    </CyberCard>
  );
}
