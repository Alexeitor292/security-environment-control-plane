import { resolvePanelState } from "./data-panel";

describe("resolvePanelState", () => {
  it("shows a skeleton only for structural first loads", () => {
    expect(
      resolvePanelState({ loading: true, error: null, hasData: false }),
    ).toBe("skeleton");
  });

  it("never shows a skeleton over cached data (reload keeps content)", () => {
    expect(
      resolvePanelState({ loading: true, error: null, hasData: true }),
    ).toBe("content");
  });

  it("shows the error state when a load failed and nothing is cached", () => {
    expect(
      resolvePanelState({ loading: false, error: "api_unreachable", hasData: false }),
    ).toBe("error");
  });

  it("keeps stale content visible when a reload fails", () => {
    expect(
      resolvePanelState({ loading: false, error: "boom", hasData: true }),
    ).toBe("content");
  });

  it("distinguishes empty data from missing data", () => {
    expect(
      resolvePanelState({ loading: false, error: null, hasData: true, isEmpty: true }),
    ).toBe("empty");
    expect(
      resolvePanelState({ loading: false, error: null, hasData: true, isEmpty: false }),
    ).toBe("content");
    expect(
      resolvePanelState({ loading: false, error: null, hasData: false }),
    ).toBe("empty");
  });
});
