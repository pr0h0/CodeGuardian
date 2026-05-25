import { describe, expect, it } from "vitest";
import { classifyFileRole, fileRoleScore } from "../../src/repo/fileRole.js";

describe("file role classification", () => {
  it("classifies runtime source separately from tests, fixtures, client, CI, and generated code", () => {
    expect(classifyFileRole("routes/login.ts")).toBe("server-runtime");
    expect(classifyFileRole("src/controllers/adminController.ts")).toBe("server-runtime");
    expect(classifyFileRole("frontend/src/app/Services/user.service.ts")).toBe("client");
    expect(classifyFileRole("test/api/login.test.ts")).toBe("test");
    expect(classifyFileRole("data/static/codefixes/example.ts")).toBe("fixture");
    expect(classifyFileRole(".github/workflows/scan.yml")).toBe("ci");
    expect(classifyFileRole("dist/bundle.min.js")).toBe("generated");
    expect(classifyFileRole("package-lock.json")).toBe("dependency");
  });

  it("gives runtime files higher scan priority than reusable non-runtime roles", () => {
    expect(fileRoleScore("server-runtime")).toBeGreaterThan(fileRoleScore("client"));
    expect(fileRoleScore("client")).toBeGreaterThan(fileRoleScore("fixture"));
    expect(fileRoleScore("fixture")).toBeGreaterThan(fileRoleScore("generated"));
  });
});
