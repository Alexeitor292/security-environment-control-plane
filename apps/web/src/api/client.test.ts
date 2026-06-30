import { describe, expect, it } from "vitest";

import { buildUrl } from "./client";

describe("buildUrl", () => {
  it("joins a path onto the API base", () => {
    const url = buildUrl("/api/v1/templates");
    expect(url).toContain("/api/v1/templates");
  });

  it("appends query params", () => {
    const url = buildUrl("/api/v1/audit", { exercise_id: "abc" });
    expect(url).toContain("exercise_id=abc");
  });
});
