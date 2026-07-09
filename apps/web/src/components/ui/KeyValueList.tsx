import clsx from "clsx";
import type { ReactNode } from "react";

export interface KeyValueItem {
  key: string;
  value: ReactNode;
  /** Render the value in the mono evidence typeface (hashes, identities). */
  mono?: boolean;
}

/** The dl.kv metadata idiom (ownership, plan hash, lifecycle, rollback
 *  posture) as one component. */
export function KeyValueList({
  items,
  className,
}: {
  items: KeyValueItem[];
  className?: string;
}) {
  return (
    <dl className={clsx("ui-kv", className)}>
      {items.map((item) => (
        <div className="ui-kv__row" key={item.key}>
          <dt>{item.key}</dt>
          <dd className={clsx(item.mono && "mono")}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
