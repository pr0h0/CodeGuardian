import fs from "node:fs";
import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";
import { lineAtOffset } from "../utils/lineMap.js";
import { redactSecrets } from "../utils/redact.js";
import type { Severity } from "../config/defaults.js";

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  regex: string;
  extensions?: string[];
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
        const line = lineAtOffset(file.content, match.index ?? 0);
        results.push({
          scanner: "custom-rules",
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          path: file.path,
          startLine: line,
          endLine: line,
          message: redactSecrets(match[0].slice(0, 300)),
          raw: { rule }
        });
      }
    }
  }
  return results;
}
