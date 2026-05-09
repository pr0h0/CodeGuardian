import { describe, expect, it } from "vitest";
import { assertAllowedExecutable, requestNeedsApproval } from "../../src/tools/policy.js";

describe("policy", () => {
  it("blocks shell", () => {
    expect(() => assertAllowedExecutable("bash")).toThrow();
  });
  it("requires approval for external host", () => {
    expect(requestNeedsApproval("GET", "https://example.com", ["localhost"])).toBe(true);
  });
});
