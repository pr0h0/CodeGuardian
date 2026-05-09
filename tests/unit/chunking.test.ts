import { describe, expect, it } from "vitest";
import { buildChunks } from "../../src/repo/repoIndexer.js";

describe("chunking", () => {
  it("uses overlapping windows", () => {
    const content = Array.from({ length: 250 }, (_, i) => `line ${i}`).join("\n");
    const chunks = buildChunks(content, 120, 20);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks[1].startLine).toBe(101);
  });
});
