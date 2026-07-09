// Render-state resolution for DataPanel over the shared AsyncState shape.
//
// Skeletons show only for structural (first) loads — never for cached data:
// a reload with data already present keeps the content visible.

export type PanelState = "skeleton" | "error" | "empty" | "content";

export interface PanelStateInput {
  loading: boolean;
  error: string | null;
  hasData: boolean;
  /** Data is present but has nothing to show (e.g. an empty list). */
  isEmpty?: boolean;
}

export function resolvePanelState(input: PanelStateInput): PanelState {
  if (input.hasData) {
    return input.isEmpty ? "empty" : "content";
  }
  if (input.loading) return "skeleton";
  if (input.error !== null) return "error";
  return "empty";
}
