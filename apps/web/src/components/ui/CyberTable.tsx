import clsx from "clsx";
import type { ReactNode } from "react";

export interface CyberTableProps {
  head: ReactNode[];
  /** Table body rows (<tr> elements). */
  children: ReactNode;
  /** Footer caption line (e.g. "2 targets · secret references are opaque
   *  pointers"). Pass exported constants for safety-relevant captions. */
  caption?: ReactNode;
  className?: string;
}

/** Tokenized data table with uppercase letterspaced headers and its own
 *  horizontal-overflow container. */
export function CyberTable({
  head,
  caption,
  children,
  className,
}: CyberTableProps) {
  return (
    <div className={clsx("ui-table-wrap", className)}>
      <table className="ui-table">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
      {caption !== undefined && (
        <div className="ui-table__caption">{caption}</div>
      )}
    </div>
  );
}
