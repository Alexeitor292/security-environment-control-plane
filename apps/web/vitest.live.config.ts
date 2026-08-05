// Config for the LIVE acceptance run (`npm run test:live`).
//
// Separate from vite.config.ts purely so the `*.live-test.ts` files are excluded from the default
// `npm test` gate — the Frontend CI job has no control plane to point them at. The naming is
// deliberate: `.live-test.ts` does not match vitest's default `*.test.ts` glob, so these can never
// be picked up by the normal run by accident.
//
// This is NOT a way to skip them. They have no skip guard; run without a reachable API they fail.

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.live-test.ts"],
    // A real deploy/reset/destroy against a live provider is not instant.
    testTimeout: 120_000,
    hookTimeout: 180_000,
  },
});
