import clsx from "clsx";
import { useRef } from "react";

export interface TabItem {
  id: string;
  label: string;
}

export interface TabRailProps {
  tabs: TabItem[];
  active: string;
  onSelect: (id: string) => void;
  /** Prefix for tab/panel ids (aria-controls wiring). */
  idBase: string;
  "aria-label"?: string;
}

export function tabPanelId(idBase: string, tabId: string): string {
  return `${idBase}-panel-${tabId}`;
}

export function tabId(idBase: string, id: string): string {
  return `${idBase}-tab-${id}`;
}

/** Pill tab rail with roving-focus arrow-key navigation. The caller renders
 *  the active panel with role="tabpanel", id=tabPanelId(...), and
 *  aria-labelledby=tabId(...). */
export function TabRail({
  tabs,
  active,
  onSelect,
  idBase,
  "aria-label": ariaLabel,
}: TabRailProps) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKeyDown = (e: React.KeyboardEvent, index: number) => {
    let next: number;
    if (e.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    else return;
    e.preventDefault();
    refs.current[next]?.focus();
    onSelect(tabs[next].id);
  };

  return (
    <div className="ui-tabs" role="tablist" aria-label={ariaLabel}>
      {tabs.map((tab, i) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={tabId(idBase, tab.id)}
            aria-selected={selected}
            // Only the selected tab's panel is mounted; a dangling idref on
            // the others would be an invalid aria-controls.
            aria-controls={selected ? tabPanelId(idBase, tab.id) : undefined}
            tabIndex={selected ? 0 : -1}
            className={clsx("ui-tab", selected && "ui-tab--active")}
            onClick={() => onSelect(tab.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}
