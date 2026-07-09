import { shortId, truncateHash } from "./hash-chip";

describe("truncateHash", () => {
  it("keeps the algorithm prefix and truncates the digest", () => {
    expect(
      truncateHash("sha256:9f2c41d7a8b3e6f0aa12bb34cc56dd78"),
    ).toBe("sha256:9f2c41d7a8b3…");
  });

  it("truncates plain opaque ids without inventing a prefix", () => {
    expect(truncateHash("7c1f20aa4b7de91c02aa9f2c41d7a8b3")).toBe(
      "7c1f20aa4b7d…",
    );
  });

  it("returns short values unchanged with no trailing ellipsis", () => {
    expect(truncateHash("sha256:9f2c41d7")).toBe("sha256:9f2c41d7");
    expect(truncateHash("abc123")).toBe("abc123");
    expect(truncateHash("")).toBe("");
  });

  it("honors a custom digit count", () => {
    expect(truncateHash("sha256:4b7de91c02aa77aa", { digits: 8 })).toBe(
      "sha256:4b7de91c…",
    );
  });

  it("reproduces the prefix-stripped page dialect (hash.slice(7, 19) + '…')", () => {
    const hash = "sha256:4b7de91c02aa77aa99bb";
    expect(truncateHash(hash, { prefix: "strip" })).toBe(hash.slice(7, 19) + "…");
  });

  it("reproduces the bare no-ellipsis id dialect (id.slice(0, 8))", () => {
    expect(
      truncateHash("7c1f20aa4b7de91c", { digits: 8, ellipsis: false }),
    ).toBe("7c1f20aa");
  });

  it("does not treat UUID dashes or plain text as an algorithm prefix", () => {
    // A colon must terminate a lowercase alphanumeric prefix to count.
    expect(truncateHash("e5a2f1b8-c9d0-4b7d-91c0-2aa9f2c41d7a", { digits: 8 })).toBe(
      "e5a2f1b8…",
    );
  });
});

describe("shortId", () => {
  it("produces the 8-character id form used in metadata lines", () => {
    expect(shortId("7c1f20aa4b7de91c")).toBe("7c1f20aa…");
    expect(shortId("short")).toBe("short");
  });
});
