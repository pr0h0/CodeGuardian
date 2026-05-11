import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";
import { lineAtOffset } from "../utils/lineMap.js";

interface ConfigRule {
  id: string;
  title: string;
  category: string;
  severity: ScannerResult["severity"];
  regex: RegExp;
  paths?: RegExp[];
  cwe: string;
  fix: string;
}

const rules: ConfigRule[] = [
  { id: "rails-force-ssl-disabled", title: "Rails force_ssl disabled", category: "misconfiguration", severity: "medium", regex: /config\.force_ssl\s*=\s*false/, paths: [/config\/environments\/production\.rb$/], cwe: "CWE-319", fix: "Enable config.force_ssl in production." },
  { id: "rails-secret-key-base-hardcoded", title: "Rails secret_key_base hardcoded", category: "secrets", severity: "high", regex: /secret_key_base\s*=\s*['"][^'"]{16,}['"]/, cwe: "CWE-798", fix: "Load secret_key_base from credentials or environment variables." },
  { id: "laravel-debug-enabled", title: "Laravel debug mode enabled", category: "misconfiguration", severity: "medium", regex: /APP_DEBUG\s*=\s*true/i, paths: [/(^|\/)\.env(\.|$)?/], cwe: "CWE-489", fix: "Set APP_DEBUG=false outside local development." },
  { id: "php-display-errors-enabled", title: "PHP display_errors enabled", category: "misconfiguration", severity: "medium", regex: /display_errors\s*=\s*(1|on|true)/i, cwe: "CWE-209", fix: "Disable display_errors in production and log errors server-side." },
  { id: "django-debug-enabled", title: "Django DEBUG enabled", category: "misconfiguration", severity: "medium", regex: /\bDEBUG\s*=\s*True\b/, cwe: "CWE-489", fix: "Set DEBUG=False in production settings." },
  { id: "flask-debug-enabled", title: "Flask debug mode enabled", category: "misconfiguration", severity: "medium", regex: /\bdebug\s*=\s*True\b|FLASK_DEBUG\s*=\s*1/i, cwe: "CWE-489", fix: "Disable Flask debug mode outside local development." },
  { id: "cookie-secure-disabled", title: "Cookie secure flag disabled", category: "misconfiguration", severity: "medium", regex: /(secure\s*[:=]\s*false|SESSION_COOKIE_SECURE\s*=\s*False|httponly\s*[:=]\s*false)/i, cwe: "CWE-614", fix: "Set Secure and HttpOnly cookie flags for session cookies." },
  { id: "permissive-bind-address", title: "Service binds to all interfaces", category: "misconfiguration", severity: "low", regex: /(host\s*[:=]\s*['"]0\.0\.0\.0['"]|listen\s*\([^)]*0\.0\.0\.0)/i, cwe: "CWE-200", fix: "Bind internal services to localhost or restrict network access." },
  { id: "wordPress-debug-enabled", title: "WordPress debug mode enabled", category: "misconfiguration", severity: "medium", regex: /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/i, cwe: "CWE-489", fix: "Disable WP_DEBUG in production." }
];

export function runConfigChecks(files: IndexedFile[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files) {
    for (const rule of rules) {
      if (rule.paths && !rule.paths.some((pattern) => pattern.test(file.path))) continue;
      const regex = new RegExp(rule.regex.source, rule.regex.flags.includes("g") ? rule.regex.flags : `${rule.regex.flags}g`);
      for (const match of file.content.matchAll(regex)) {
        const line = lineAtOffset(file.content, match.index ?? 0);
        results.push({
          scanner: "config-checks",
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          path: file.path,
          startLine: line,
          endLine: line,
          message: rule.fix,
          raw: { cwe: rule.cwe, fix: rule.fix, owasp: "A05:2021-Security Misconfiguration" }
        });
      }
    }
  }
  return results;
}
