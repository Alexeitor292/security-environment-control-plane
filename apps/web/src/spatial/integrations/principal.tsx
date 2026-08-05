// The authenticated principal, made available to the spatial tree.
//
// WHY A CONTEXT RATHER THAN `useAuth()` AT EACH CALL SITE. `useAuth` throws
// outside `<AuthProvider>`, and the spatial shell is mounted in two places: the
// `/spatial` route, which sits inside the provider, and `ShellHarness`, which
// does not and must not — the harness exists to compare the shell against the
// donor without a control plane. A page calling `useAuth` directly would work in
// one and crash in the other.
//
// THE DEFAULT IS DENY, AND THAT IS THE LOAD-BEARING DECISION. With no provider
// the permission set is EMPTY, so every gated surface renders as unavailable.
// The alternative — treating "no principal" as "unrestricted", which is what a
// permissive default amounts to — would make the harness show gated content and
// would make any future mount that forgets the provider silently open. Failing
// closed costs a harness that shows fewer panels; failing open costs a boundary.
//
// WHAT THIS IS NOT. It is not an authorization boundary. The server refuses; the
// UI reflects. A gate here changes what is *offered*, never what is *permitted*,
// and no request becomes safe because a control was not rendered.

import { createContext, useContext, type ReactNode } from "react";

/** Permissions held by the current principal. Empty means "assume nothing". */
const PermissionContext = createContext<readonly string[]>([]);

export function SpatialPrincipalProvider({
  permissions,
  children,
}: {
  permissions: readonly string[] | null | undefined;
  children: ReactNode;
}) {
  return (
    <PermissionContext.Provider value={permissions ?? []}>{children}</PermissionContext.Provider>
  );
}

export function usePermissions(): readonly string[] {
  return useContext(PermissionContext);
}

/**
 * Does the principal hold ANY of these?
 *
 * `any` rather than `all` because that is what the shipped `resolveNavItem` uses
 * and the two must not disagree: a surface reachable from the sidebar and denied
 * by its own page would be a worse experience than either rule alone.
 */
export function holdsAny(held: readonly string[], required: readonly string[]): boolean {
  return required.length === 0 || required.some((p) => held.includes(p));
}

/**
 * Renders `children` when the principal holds one of `requires`, and an explicit
 * unavailable notice otherwise.
 *
 * DELIBERATELY NOT `null`. A surface that vanishes tells the operator nothing and
 * reads as a missing feature or a broken page; a surface that says which
 * permission it needs is actionable. This mirrors `resolveNavItem`, which
 * replaces a gated item with an `unavailableReason` rather than dropping it.
 */
export function PermissionGate({
  requires,
  surface,
  children,
}: {
  requires: readonly string[];
  /** What is being withheld, in the operator's words. */
  surface: string;
  children: ReactNode;
}) {
  const held = usePermissions();
  if (holdsAny(held, requires)) return <>{children}</>;

  return (
    <div className="c-state" role="status" data-testid="spatial-permission-gate">
      <strong>{surface} is not available to you</strong>
      <p className="u-secondary u-small">
        Requires {requires.map((r) => `\`${r}\``).join(" or ")}. This page reflects what the control
        plane will serve; it does not decide it.
      </p>
    </div>
  );
}
