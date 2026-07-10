import type { ReactNode } from "react";

export interface CyberTableProps {
  head: ReactNode[];
  /** Table body rows (<tr> elements). */
  children: ReactNode;
  /** Footer caption line (e.g. "2 targets · secret references are opaque
   *  pointers"). Pass exported constants for safety-relevant captions. */
  caption?: ReactNode;
  /** Accessible name for the table and its scrollable region. */
  label?: string;
  className?: string;
}

/** Tokenized data table with uppercase letterspaced headers and its own
 *  horizontal-overflow container (keyboard-scrollable). */
export function CyberTable({
  head,
  caption,
  label,
  children,
  className,
}: CyberTableProps) {
  return (
    <div className={className}>
      <div
        className="ui-table-wrap"
        tabIndex={0}
        role="region"
        aria-label={label}
      >
        <table className="ui-table" aria-label={label}>
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
      </div>
      {caption !== undefined && (
        <div className="ui-table__caption">{caption}</div>
      )}
    </div>
  );
}
