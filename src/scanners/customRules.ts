import fs from "node:fs";
import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";
import { lineAtOffset } from "../utils/lineMap.js";
import { redactSecrets } from "../utils/redact.js";
import type { Severity } from "../config/defaults.js";
import { classifySecret } from "../utils/secretClassifier.js";

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  regex: string;
  extensions?: string[];
  description?: string;
  fix?: string;
  cwe?: string;
  owasp?: string;
  confidence?: "high" | "medium" | "low";
  references?: string[];
}

export function loadCustomRules(rulePath = path.resolve("rules/custom/dangerous-patterns.json")): Rule[] {
  return JSON.parse(fs.readFileSync(rulePath, "utf8")) as Rule[];
}

export function runCustomRules(files: IndexedFile[], rules = loadCustomRules()): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files) {
    const ext = path.extname(file.path);
    for (const rule of rules) {
      if (rule.extensions && !rule.extensions.includes(ext)) continue;
      const regex = new RegExp(rule.regex, "gim");
      for (const match of file.content.matchAll(regex)) {
        if (shouldSkipMatch(rule, match[0])) continue;
        const line = lineAtOffset(file.content, match.index ?? 0);
        const secretClassification = rule.category === "secrets" ? classifySecret(match[0], file.path) : undefined;
        results.push({
          scanner: "custom-rules",
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          path: file.path,
          startLine: line,
          endLine: line,
          message: scannerMessage(match[0], secretClassification),
          raw: { rule: enrichRule(rule), secretClassification }
        });
      }
    }
  }
  return results;
}

function scannerMessage(match: string, secretClassification?: ReturnType<typeof classifySecret>): string {
  const redacted = redactSecrets(match.slice(0, 300));
  if (!secretClassification) return redacted;
  return `${redacted} (secret classification: ${secretClassification.kind}, confidence: ${secretClassification.confidence})`;
}

function shouldSkipMatch(rule: Rule, text: string): boolean {
  if (rule.category !== "secrets") return false;
  const assignedValue = text.match(/[:=]\s*(.+)$/s)?.[1]?.trim();
  if (!assignedValue) return false;

  return isRuntimeSecretReference(assignedValue);
}

function isRuntimeSecretReference(value: string): boolean {
  const normalized = value.replace(/[),;\]}]+$/g, "").trim();
  return [
    /^process\.env(?:\.[A-Z0-9_]+|\[['"][A-Z0-9_]+['"]\])$/i,
    /^import\.meta\.env(?:\.[A-Z0-9_]+|\[['"][A-Z0-9_]+['"]\])$/i,
    /^Deno\.env\.get\($/i,
    /^Deno\.env\.get\(\s*['"]$/i,
    /^Deno\.env\.get\(\s*['"][A-Z0-9_]+['"]?\s*$/i,
    /^ENV\[$/i,
    /^ENV\[\s*['"]$/i,
    /^ENV\[\s*['"][A-Z0-9_]+['"]\s*$/i,
    /^os\.environ(?:\.get\(|\[)$/i,
    /^os\.environ(?:\.get\(\s*['"]|\[\s*['"])$/i,
    /^os\.environ(?:\.get\(\s*['"][A-Z0-9_]+['"]?\s*|\[\s*['"][A-Z0-9_]+['"]?\s*)$/i,
    /^getenv\($/i,
    /^getenv\(\s*['"]$/i,
    /^getenv\(\s*['"][A-Z0-9_]+['"]?\s*$/i
  ].some((pattern) => pattern.test(normalized));
}

function enrichRule(rule: Rule): Rule {
  const meta = categoryDefaults[rule.category] ?? categoryDefaults.security;
  return {
    description: meta.description,
    fix: meta.fix,
    cwe: meta.cwe,
    owasp: meta.owasp,
    confidence: "medium",
    references: meta.references,
    ...rule
  };
}

const categoryDefaults: Record<string, Pick<Rule, "description" | "fix" | "cwe" | "owasp" | "references">> = {
  "command-injection": { cwe: "CWE-78", owasp: "A03:2021-Injection", description: "Untrusted input may reach an operating-system command sink.", fix: "Avoid shell execution; use safe APIs with argument arrays and strict allowlists.", references: ["https://cwe.mitre.org/data/definitions/78.html"] },
  "sql-injection": { cwe: "CWE-89", owasp: "A03:2021-Injection", description: "Untrusted input may be concatenated into SQL.", fix: "Use parameterized queries and avoid string interpolation for SQL.", references: ["https://cwe.mitre.org/data/definitions/89.html"] },
  "xss": { cwe: "CWE-79", owasp: "A03:2021-Injection", description: "Untrusted input may be rendered as executable markup.", fix: "Escape output by context and avoid raw HTML rendering.", references: ["https://cwe.mitre.org/data/definitions/79.html"] },
  "ssrf": { cwe: "CWE-918", owasp: "A10:2021-Server-Side Request Forgery", description: "Untrusted input may control an outbound request URL.", fix: "Use URL allowlists, block internal ranges, and resolve DNS safely.", references: ["https://cwe.mitre.org/data/definitions/918.html"] },
  "path-traversal": { cwe: "CWE-22", owasp: "A01:2021-Broken Access Control", description: "Untrusted input may control filesystem paths.", fix: "Normalize paths, enforce a base directory, and allowlist filenames.", references: ["https://cwe.mitre.org/data/definitions/22.html"] },
  "file-inclusion": { cwe: "CWE-98", owasp: "A03:2021-Injection", description: "Untrusted input may control included code or files.", fix: "Map user choices to fixed server-side files and reject arbitrary paths.", references: ["https://cwe.mitre.org/data/definitions/98.html"] },
  "deserialization": { cwe: "CWE-502", owasp: "A08:2021-Software and Data Integrity Failures", description: "Untrusted serialized data may instantiate attacker-controlled objects.", fix: "Use safe formats such as JSON and never deserialize untrusted objects.", references: ["https://cwe.mitre.org/data/definitions/502.html"] },
  "prototype-pollution": { cwe: "CWE-1321", owasp: "A03:2021-Injection", description: "User-controlled object keys may mutate Object prototypes or security-sensitive defaults.", fix: "Reject __proto__, prototype, and constructor keys before merge/assignment; use schema validation and safe merge helpers.", references: ["https://cwe.mitre.org/data/definitions/1321.html"] },
  "open-redirect": { cwe: "CWE-601", owasp: "A01:2021-Broken Access Control", description: "Untrusted input may control a redirect target.", fix: "Redirect only to relative paths or allowlisted origins.", references: ["https://cwe.mitre.org/data/definitions/601.html"] },
  "transport-security": { cwe: "CWE-295", owasp: "A02:2021-Cryptographic Failures", description: "TLS certificate validation may be disabled.", fix: "Keep certificate and hostname verification enabled.", references: ["https://cwe.mitre.org/data/definitions/295.html"] },
  "weak-crypto": { cwe: "CWE-327", owasp: "A02:2021-Cryptographic Failures", description: "Weak cryptographic primitives may be used.", fix: "Use modern approved algorithms and keyed hashes where appropriate.", references: ["https://cwe.mitre.org/data/definitions/327.html"] },
  "secrets": { cwe: "CWE-798", owasp: "A07:2021-Identification and Authentication Failures", description: "Secret material may be committed to source.", fix: "Move secrets to a secret manager, rotate exposed values, and scrub history if needed.", references: ["https://cwe.mitre.org/data/definitions/798.html"] },
  "misconfiguration": { cwe: "CWE-16", owasp: "A05:2021-Security Misconfiguration", description: "Configuration may weaken application security.", fix: "Use production-safe defaults and enforce secure settings in deployment.", references: ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"] },
  "auth": { cwe: "CWE-287", owasp: "A07:2021-Identification and Authentication Failures", description: "Authentication or authorization logic may need review.", fix: "Require server-side authorization checks on every sensitive action.", references: ["https://cwe.mitre.org/data/definitions/287.html"] },
  security: { cwe: "CWE-200", owasp: "A01:2021-Broken Access Control", description: "Security-sensitive pattern needs manual review.", fix: "Validate the data flow and apply a context-specific fix.", references: ["https://owasp.org/Top10/"] }
};
