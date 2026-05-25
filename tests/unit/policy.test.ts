import { describe, expect, it } from "vitest";
import { assertAllowedExecutable, requestNeedsApproval } from "../../src/tools/policy.js";
import { browserRequestAllowed } from "../../src/tools/puppeteerTool.js";

describe("policy", () => {
  it("blocks shell", () => {
    expect(() => assertAllowedExecutable("bash")).toThrow();
  });
  it("requires approval for external host", () => {
    expect(requestNeedsApproval("GET", "https://example.com", ["localhost"])).toBe(true);
  });

  it("allows browser requests only to allowlisted hosts or local document schemes", () => {
    expect(browserRequestAllowed("http://localhost:3000/app.js", ["localhost"])).toBe(true);
    expect(browserRequestAllowed("https://cdn.example.com/app.js", ["localhost"])).toBe(false);
    expect(browserRequestAllowed("data:image/png;base64,AA==", ["localhost"])).toBe(true);
    expect(browserRequestAllowed("about:blank", ["localhost"])).toBe(true);
  });
});
