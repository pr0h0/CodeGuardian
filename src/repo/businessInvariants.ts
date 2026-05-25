import type { IndexedFile } from "./repoIndexer.js";
import { detectRoutes } from "./routeDetector.js";
import type { ScannerResult } from "../scanners/types.js";

export interface BusinessInvariant {
  id: string;
  title: string;
  category: "ownership" | "tenant-isolation" | "financial-integrity" | "workflow-state";
  path: string;
  line: number;
  rule: string;
  evidence: string;
  confidence: "high" | "medium" | "low";
}

const objectIdPattern = /\b(req|request)\.(params|body|query)\.(userId|user_id|ownerId|owner_id|tenantId|tenant_id|orgId|organizationId|accountId|customerId|basketId|cartId|orderId|invoiceId|paymentId|reviewId|id)\b/i;
const ownershipGuardPattern = /\b(authorize|authorize!|policy|can\?|requireOwner|requirePermission|isAuthorized|ownership|belongsTo|scopeToCurrentUser|current_user|req\.user|request\.user|ctx\.user|session\.user|tenantId\s*:|ownerId\s*:|userId\s*:)\b/i;
const financialFieldPattern = /\b(req|request)\.(body|query|params)\.(price|amount|total|quantity|qty|discount|coupon|balance|credit)\b/i;
const workflowPattern = /\b(status|state|stage|approved|confirmed|paid|checkout|payment|publish|activate|deactivate|delete|cancel|refund)\b/i;
const writePattern = /\b(create|update|save|delete|destroy|remove|checkout|charge|refund|confirm|approve|publish|activate)\s*\(/i;
const tenantPattern = /\b(tenantId|tenant_id|orgId|organizationId|organisationId|accountId|workspaceId)\b/i;

export function discoverBusinessInvariants(files: IndexedFile[]): BusinessInvariant[] {
  const invariants: BusinessInvariant[] = [];
  for (const file of sourceFiles(files)) {
    const lines = file.content.split(/\r?\n/);
    for (const route of detectRoutes(file.path, file.content)) {
      const window = windowText(lines, route.startLine, 14);
      if (objectIdPattern.test(window) || /:([A-Za-z_]*(?:id|Id))\b/.test(route.routePath)) {
        invariants.push(invariant("ownership", file.path, route.startLine, `Route ${route.method} ${route.routePath} must bind request object identifiers to the authenticated subject or tenant.`, window));
      }
      if (tenantPattern.test(window)) {
        invariants.push(invariant("tenant-isolation", file.path, route.startLine, `Route ${route.method} ${route.routePath} must enforce tenant or organization scope on every read and write.`, window));
      }
      if (financialFieldPattern.test(window) || /\b(cart|basket|checkout|order|payment|coupon|discount)\b/i.test(route.routePath)) {
        invariants.push(invariant("financial-integrity", file.path, route.startLine, `Route ${route.method} ${route.routePath} must compute prices, totals, discounts, and quantities server-side or validate them against trusted state.`, window));
      }
      if (workflowPattern.test(window) && writePattern.test(window)) {
        invariants.push(invariant("workflow-state", file.path, route.startLine, `Route ${route.method} ${route.routePath} must enforce the prior workflow state before applying side effects.`, window));
      }
    }
  }
  return dedupeInvariants(invariants).slice(0, 200);
}

export function runBusinessInvariantChecks(files: IndexedFile[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of sourceFiles(files)) {
    const lines = file.content.split(/\r?\n/);
    for (const route of detectRoutes(file.path, file.content)) {
      const window = windowText(lines, route.startLine, 18);
      if ((objectIdPattern.test(window) || /:([A-Za-z_]*(?:id|Id))\b/.test(route.routePath))
        && /(findById|findOne|findUnique|findFirst|update|delete|destroy|remove|save|create)\s*\(/i.test(window)
        && !ownershipGuardPattern.test(window)) {
        results.push(result(
          "business-invariant-missing-ownership-guard",
          "Route uses request-controlled object identifiers without an obvious ownership guard",
          "high",
          file.path,
          route.startLine,
          `${route.method} ${route.routePath}`
        ));
      }
      if (financialFieldPattern.test(window)
        && /(create|update|save|checkout|charge|purchase|add|apply|calculate)\s*\(/i.test(window)
        && !/\b(recalculate|serverCalculated|priceService|catalog|inventory|validate|schema|allowlist|pick)\b/i.test(window)) {
        results.push(result(
          "business-invariant-client-financial-field",
          "Business-critical financial field appears trusted from request data",
          "medium",
          file.path,
          route.startLine,
          `${route.method} ${route.routePath}`
        ));
      }
      if (workflowPattern.test(window) && writePattern.test(window) && !/\b(status\s*===|state\s*===|assertState|requireState|transition|nonce|csrf|approved|paid)\b/i.test(window)) {
        results.push(result(
          "business-invariant-missing-workflow-state-guard",
          "Workflow side effect lacks an obvious prior-state guard",
          "medium",
          file.path,
          route.startLine,
          `${route.method} ${route.routePath}`
        ));
      }
    }
  }
  return dedupeResults(results);
}

function invariant(category: BusinessInvariant["category"], path: string, line: number, rule: string, evidence: string): BusinessInvariant {
  return {
    id: `${category}:${path}:${line}`,
    title: categoryTitle(category),
    category,
    path,
    line,
    rule,
    evidence: evidence.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).slice(0, 6).join(" | ").slice(0, 700),
    confidence: category === "ownership" || category === "tenant-isolation" ? "high" : "medium"
  };
}

function categoryTitle(category: BusinessInvariant["category"]): string {
  switch (category) {
    case "ownership":
      return "Object ownership must be enforced";
    case "tenant-isolation":
      return "Tenant scope must dominate data access";
    case "financial-integrity":
      return "Financial values must be server-trusted";
    case "workflow-state":
      return "Workflow state must be enforced before side effects";
  }
}

function result(ruleId: string, title: string, severity: ScannerResult["severity"], path: string, line: number, message: string): ScannerResult {
  return {
    scanner: "business-invariants",
    ruleId,
    title,
    category: "business-logic",
    severity,
    path,
    startLine: line,
    endLine: line,
    message,
    raw: {
      description: "Static business-invariant seed for authorization and workflow review.",
      confidence: severity === "high" ? "high" : "medium"
    }
  };
}

function windowText(lines: string[], startLine: number, radius: number): string {
  const start = Math.max(0, startLine - 1);
  const end = Math.min(lines.length, start + radius);
  return lines.slice(start, end).join("\n");
}

function sourceFiles(files: IndexedFile[]): IndexedFile[] {
  return files.filter((file) => /\.(js|jsx|mjs|cjs|ts|tsx|py|php|rb|go|java|cs)$/i.test(file.path));
}

function dedupeInvariants(invariants: BusinessInvariant[]): BusinessInvariant[] {
  const seen = new Set<string>();
  return invariants.filter((item) => {
    const key = `${item.category}:${item.path}:${item.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dedupeResults(results: ScannerResult[]): ScannerResult[] {
  const seen = new Set<string>();
  return results.filter((item) => {
    const key = `${item.ruleId}:${item.path}:${item.startLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
