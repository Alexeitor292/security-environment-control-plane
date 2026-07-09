// Compatibility re-export: StatusBadge is now a design-system primitive with
// explicit tone maps for every known status union (see ui/status-tone.ts).
// Existing call sites keep this import path; new code should import from
// "@/components/ui".
export { StatusBadge, type StatusBadgeProps } from "./ui/StatusBadge";
