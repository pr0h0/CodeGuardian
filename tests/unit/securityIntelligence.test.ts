import { describe, expect, it } from "vitest";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { discoverBusinessInvariants, runBusinessInvariantChecks } from "../../src/repo/businessInvariants.js";
import { buildSecurityIntelligence, boundaryForPath } from "../../src/repo/securityIntelligence.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function file(filePath: string, content: string, language = "typescript"): IndexedFile {
  return { path: filePath, absolutePath: filePath, language, content, lineCount: content.split(/\r?\n/).length };
}

function scannerResult(overrides: Partial<ScannerResult>): ScannerResult {
  return {
    scanner: "source-patterns",
    ruleId: "source-request-controlled-object-id",
    title: "Request-controlled object identifier is used without an ownership check",
    category: "authorization",
    severity: "high",
    path: "src/routes/orders.ts",
    startLine: 4,
    endLine: 4,
    message: "Order.findById(req.params.orderId)",
    ...overrides
  };
}

describe("security intelligence", () => {
  it("builds a persistent attack-surface artifact with boundaries, catalog entries, invariants, and negative evidence", () => {
    const files = [
      file("src/routes/orders.ts", [
        "import express from 'express';",
        "const router = express.Router();",
        "router.get('/orders/:orderId', async (req, res) => {",
        "  const order = await Order.findById(req.params.orderId);",
        "  res.json(order);",
        "});",
        "export function sanitizePath(value) { return path.basename(value); }"
      ].join("\n")),
      file("src/client/App.tsx", "export function App() { return <div />; }")
    ];

    const intelligence = buildSecurityIntelligence(files, [scannerResult({})], {
      negativeEvidence: [{ title: "Old false positive", path: "src/routes/orders.ts", startLine: 4, reason: "previously rejected", status: "false_positive" }],
      aiSourceMap: {
        summary: "orders route needs authorization review",
        globalPriorityFiles: ["src/routes/orders.ts"],
        priorityFilesByClass: { authz: ["src/routes/orders.ts"] },
        notes: ["custom guard missing"],
        catalog: {
          sources: [{ name: "req.params.orderId", path: "src/routes/orders.ts", line: 4, category: "request", evidence: "route param" }],
          sinks: [],
          sanitizers: [],
          guards: [{ name: "requireOwner", path: "src/routes/orders.ts", line: 3, category: "authorization", evidence: "AI-discovered guard naming convention" }]
        }
      }
    });

    expect(intelligence.entrypoints).toEqual(expect.arrayContaining([
      expect.objectContaining({ method: "GET", routePath: "/orders/:orderId", path: "src/routes/orders.ts" })
    ]));
    expect(intelligence.boundaries).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "server-runtime" }),
      expect.objectContaining({ kind: "client" })
    ]));
    expect(intelligence.catalog).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "source", name: expect.stringContaining("req.params") }),
      expect.objectContaining({ kind: "guard", discoveredBy: "ai", name: "requireOwner" })
    ]));
    expect(intelligence.invariants.some((item) => item.category === "ownership")).toBe(true);
    expect(intelligence.negativeEvidence).toHaveLength(1);
    expect(intelligence.highRiskFiles[0].path).toBe("src/routes/orders.ts");
  });

  it("discovers business invariants and emits static findings when side effects lack a server-side guard", () => {
    const files = [
      file("src/routes/cart.ts", [
        "app.post('/cart/:basketId/checkout', async (req, res) => {",
        "  const basket = await Basket.findById(req.params.basketId);",
        "  await Order.create({ userId: req.body.userId, total: req.body.price });",
        "  res.json({ ok: true });",
        "});"
      ].join("\n"))
    ];

    const invariants = discoverBusinessInvariants(files);
    const results = runBusinessInvariantChecks(files);

    expect(invariants).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: "ownership" }),
      expect.objectContaining({ category: "financial-integrity" })
    ]));
    expect(results).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "business-invariant-missing-ownership-guard", category: "business-logic" }),
      expect.objectContaining({ ruleId: "business-invariant-client-financial-field", category: "business-logic" })
    ]));
  });

  it("assigns stable service boundaries from paths", () => {
    expect(boundaryForPath("apps/api/src/routes/users.ts").kind).toBe("server-runtime");
    expect(boundaryForPath("packages/web/src/App.tsx").kind).toBe("client");
    expect(boundaryForPath("tests/routes/users.test.ts").kind).toBe("test");
  });
});
