import { describe, expect, it } from "vitest";
import { buildScanStrategyInstructions, scanStrategyMetadata } from "../../src/core/scanStrategy.js";

describe("scan strategy", () => {
  it("renders AI instructions from project scan strategy", () => {
    const instructions = buildScanStrategyInstructions({
      vulnerabilityClasses: ["injection", "authz", "ssrf"],
      rulesOfEngagement: "No destructive requests.",
      reportFilters: {
        minSeverity: "medium",
        minConfidence: "medium",
        guidance: "Drop missing-header-only findings."
      }
    });

    expect(instructions).toContain("Vulnerability classes in scope: injection, authz, ssrf");
    expect(instructions).toContain("Rules of engagement: No destructive requests.");
    expect(instructions).toContain("Report guidance: Drop missing-header-only findings.");
  });

  it("summarizes configured scan strategy for reports", () => {
    const metadata = scanStrategyMetadata({
      focusPaths: ["src/routes/**"],
      avoidPaths: ["tests/**"],
      vulnerabilityClasses: ["ssrf"],
      reportFilters: { minSeverity: "high" }
    });

    expect(metadata).toEqual({
      focusPaths: ["src/routes/**"],
      avoidPaths: ["tests/**"],
      vulnerabilityClasses: ["ssrf"],
      rulesOfEngagement: "",
      reportFilters: { minSeverity: "high" }
    });
  });
});
