import type { ReactNode } from "react";

import { SafetyNotice } from "../../../components/ui";
import { useRange } from "../RangeLayout";
import { providerApplicability } from "./proxmox-view";

/**
 * Header every Proxmox surface renders first.
 *
 * It answers the question an operator asks before reading anything else on the page: does this
 * describe the range I am looking at? The answer is derived from the range's own recorded provider,
 * so it cannot drift from what the control plane says.
 *
 * When the answer is no, the notice is assertive (`role="alert"`, danger tone) rather than a quiet
 * aside. A Proxmox teardown screen read as applying to a Docker range is exactly the confusion
 * worth interrupting someone over.
 */
export function ProxmoxSection({ children }: { children: ReactNode }) {
  const { range } = useRange();
  const applicability = providerApplicability(range.provider);

  return (
    <>
      <SafetyNotice
        role={applicability.applies ? "note" : "alert"}
        tone={applicability.applies ? "info" : "danger"}
      >
        {applicability.note}
      </SafetyNotice>
      {children}
    </>
  );
}
