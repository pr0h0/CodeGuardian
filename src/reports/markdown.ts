import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

type Row = Record<string, any>;

function countBy(rows: Row[], key: string): Record<string, number> {
  return rows.reduce((acc, row) => {
    const value = String(row[key] ?? "unknown");
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

export function writeMarkdownReport(outDir: string, bundle: any, warnings: string[] = [], reportBase = "report"): string {
  ensureDir(outDir);
  const repoPath = String(bundle.scan?.repo_path ?? "");
  const findings = bundle.findings ?? [];
  const scanner = bundle.scannerResults ?? [];
  const codeFindings = findings.filter((item: Row) => item.category !== "dependency");
  const dependencyResults = scanner.filter(isDependencyVulnerabilityResult);
  const dependencyFindings = buildDependencyFindings(repoPath, dependencyResults);
  const confirmedCodeFindings = dedupeCodeFindings(codeFindings.filter((item: Row) => item.status !== "false_positive"));
  const falsePositives = codeFindings.filter((item: Row) => item.status === "false_positive");
  const buckets = bucketCodeFindings(confirmedCodeFindings);

  const lines = [
    "# Codeguardian Security Report",
    "",
    ...renderSection("Summary", [
      `- Scan ID: ${bundle.scan?.id ?? "unknown"}`,
      `- Repository: ${escapeHtml(repoPath || "unknown")}`,
      `- Status: ${bundle.scan?.status ?? "unknown"}`,
      `- Indexed files: ${(bundle.files ?? []).filter((file: Row) => file.indexed).length}`,
      `- Code findings: ${confirmedCodeFindings.length}`,
      `- Dependency findings: ${dependencyFindings.length}`,
      `- False positives: ${falsePositives.length}`,
      `- Suppressed findings: ${bundle.suppressions?.suppressed ?? 0}`
    ], true),
    ...renderSection("Action Plan", renderActionPlan(confirmedCodeFindings, dependencyFindings), true),
    ...renderSection("Top 5 Fix First", renderTopFixes(confirmedCodeFindings, dependencyFindings), true),
    ...renderSection("Confirmed Code Findings", renderCodeFindings(buckets.confirmed, repoPath), true, `${buckets.confirmed.length} items`),
    ...renderSection("Suspected / Needs Validation", renderCodeFindings([...buckets.suspected, ...buckets.needsDynamic], repoPath), false, `${buckets.suspected.length + buckets.needsDynamic.length} items`),
    ...renderSection("Dependency Findings", dependencyFindings.length ? dependencyFindings.flatMap((item, index) => renderDependencyFinding(item, index + 1)) : ["No vulnerable dependency findings found."], false, `${dependencyFindings.length} items`),
    ...renderSection("AI False Positives", falsePositives.length ? falsePositives.flatMap((item: Row, index: number) => renderFalsePositive(item, index + 1)) : ["No AI-triaged false positives recorded."], false, `${falsePositives.length} items`),
    ...renderSection("Additional SAST Findings", renderAdditionalSastFindings(scanner, confirmedCodeFindings, falsePositives, bundle.projectConfig?.maxAdditionalSastFindings ?? 100), false),
    ...renderSection("Noise Bucket", renderNoiseBucket(scanner), false),
    ...renderSection("Baseline Diff", renderBaselineDiff(bundle.baselineDiff), false),
    ...renderSection("Code Finding Counts", formatCounts(confirmedCodeFindings, "severity"), false),
    ...renderSection("AI Audit Coverage", renderAiAuditCoverage(repoPath, findings, bundle.files ?? []), false),
    ...renderSection("Execution", [
      ...((bundle.toolStatuses ?? []).length ? bundle.toolStatuses.map((tool: Row) => `- ${escapeHtml(tool.name)}: ${tool.available ? "available" : "missing"}${tool.version ? ` - ${escapeHtml(tool.version)}` : ""}${tool.error ? ` - ${escapeHtml(tool.error)}` : ""}`) : ["- Not recorded"]),
      "- External scanners: Docker-only execution for Semgrep, Gitleaks, Trivy, OSV-Scanner, and Bearer.",
      ...renderScannerRuns(bundle.scannerRuns ?? [])
    ], false),
    ...renderSection("AI Budget", [
      ...renderAiBudget(bundle.aiBudget),
      `- AI models: ${escapeHtml(bundle.scan?.model ?? "none")}`,
      `- AI instructions: ${bundle.aiInstructions?.loaded ? `${escapeHtml(bundle.aiInstructions.path)} (${bundle.aiInstructions.chars} chars)` : "not supplied"}`
    ], false),
    ...renderSection("Scanner Results", [
      ...["semgrep", "gitleaks", "trivy", "osv-scanner", "bearer", "custom-rules", "taint-lite", "taint-flow", "config-checks", "quality"].map((scannerName) => `- ${scannerName}: ${scanner.filter((item: Row) => item.scanner === scannerName).length} results`),
      ...(bundle.incremental?.enabled ? [`- Incremental local scan: changed files ${bundle.incremental.changedFiles}, local scanner files ${bundle.incremental.localScannerFiles}`] : [])
    ], false),
    ...renderSection("Suppressions", bundle.suppressions?.suppressed ? [`- Suppressed: ${bundle.suppressions.suppressed}`, ...(bundle.suppressions.reasons ?? []).slice(0, 20).map((reason: string) => `- ${escapeHtml(reason)}`)] : ["- None"], false),
    ...renderSection("Warnings and Errors", warnings.length ? warnings.map((warning) => `- ${firstSentence(warning, 220)}`) : ["- None"], false)
  ];
  const file = path.join(outDir, `${reportBase}.md`);
  fs.writeFileSync(file, lines.join("\n"));
  return file;
}

function formatCounts(rows: Row[], key: string): string[] {
  const counts = Object.entries(countBy(rows, key)).map(([k, v]) => `- ${k}: ${v}`);
  return counts.length ? counts : ["- None"];
}

function renderSection(title: string, body: string[], open = false, badge = ""): string[] {
  const summary = badge ? `${title} (${escapeHtml(badge)})` : title;
  return [
    `## ${title}`,
    "",
    `<details${open ? " open" : ""}>`,
    `<summary><strong>${summary}</strong></summary>`,
    "",
    ...body,
    "",
    "</details>",
    ""
  ];
}

function renderItemDetails(summary: string, body: string[], open = false): string[] {
  return [
    `<details${open ? " open" : ""}>`,
    `<summary><strong>${summary}</strong></summary>`,
    "",
    ...body,
    "",
    "</details>",
    ""
  ];
}

function renderActionPlan(findings: Row[], dependencies: DependencyFinding[]): string[] {
  const fixNow = findings.filter((item) => ["critical", "high"].includes(item.severity) && ["confirmed", "high"].includes(String(item.confidence)));
  const validate = findings.filter((item) => item.status === "suspected" || item.confidence === "medium" || item.confidence === "low");
  const topDependencies = dependencies.filter((item) => item.probability >= 70);
  const lines = [
    `- Fix now: ${fixNow.length} code findings and ${topDependencies.length} dependency packages.`,
    `- Validate manually: ${validate.length} code findings need reachability or exploitability confirmation.`,
    `- Ignore/accept: see AI false positives section before creating tickets.`,
    ""
  ];
  for (const item of fixNow.slice(0, 8)) lines.push(`- Fix now: ${escapeHtml(item.title)} @${escapeHtml(item.path ?? "unknown")}:${item.start_line ?? "?"}`);
  for (const item of topDependencies.slice(0, 5)) lines.push(`- Upgrade: ${escapeHtml(item.packageName)} (${escapeHtml(item.cves.join(", "))}) probability ${item.probability}/100`);
  return lines;
}

function renderBaselineDiff(diff?: Row): string[] {
  if (!diff?.baselineScanId) return ["- No baseline scan available. This scan becomes future baseline."];
  return [
    `- Baseline scan: ${escapeHtml(diff.baselineScanId)}`,
    `- New findings: ${diff.newFindings ?? 0}`,
    `- Resolved findings: ${diff.resolvedFindings ?? 0}`,
    `- Unchanged findings: ${diff.unchangedFindings ?? 0}`
  ];
}

function renderScannerRuns(runs: Row[]): string[] {
  if (!runs.length) return ["- Scanner run metadata: not recorded."];
  return runs.map((run) => `- ${escapeHtml(run.scanner)}: results=${run.result_count} elapsed=${Math.round((run.elapsed_ms ?? 0) / 1000)}s image=${escapeHtml(run.image ?? "unknown")}${run.warning ? ` warning=${escapeHtml(firstSentence(run.warning, 120))}` : ""}`);
}

function renderAiBudget(budget?: Row): string[] {
  if (!budget) return ["- AI was not used or budget metadata was not recorded."];
  return [
    `- Triage context chars: ${budget.triageContextChars ?? 0}`,
    `- Estimated triage tokens: ${budget.estimatedTriageTokens ?? 0}`
  ];
}

function renderTopFixes(findings: Row[], dependencies: DependencyFinding[]): string[] {
  const code = findings
    .map((item) => ({ kind: "code", score: scoreCodeExploitability(item), label: `${escapeHtml(item.title)} @${escapeHtml(item.path ?? "unknown")}:${item.start_line ?? "?"}` }))
    .filter((item) => item.score >= 60);
  const deps = dependencies
    .map((item) => ({ kind: "dependency", score: item.probability, label: `${escapeHtml(item.packageName)} ${escapeHtml(item.cves.join(", "))}` }))
    .filter((item) => item.score >= 60);
  const top = [...code, ...deps].sort((a, b) => b.score - a.score).slice(0, 5);
  return top.length ? top.map((item, index) => `${index + 1}. ${item.label} - ${item.kind}, score ${item.score}/100`) : ["No high-priority fixes identified."];
}

function renderAiAuditCoverage(repoPath: string, findings: Row[], files: Row[]): string[] {
  const aiFindings = findings.filter((item) => String(item.source ?? "").toLowerCase().includes("ai") || String(item.raw_json ?? "").includes("AI exploratory"));
  const filesWithAiFindings = [...new Set(aiFindings.map((item) => item.path).filter(Boolean))];
  const indexedCount = files.filter((file) => file.indexed).length;
  const sourceCount = walkSourceFiles(repoPath).length;
  return [
    `- Indexed files: ${indexedCount}`,
    `- Auditable source files: ${sourceCount}`,
    `- Files with AI-produced findings: ${filesWithAiFindings.length}`,
    ...(filesWithAiFindings.length ? filesWithAiFindings.slice(0, 30).map((file) => `- AI finding evidence in: ${escapeHtml(file)}`) : ["- AI audit did not produce source-code findings in this run."]),
    "- Console logs show each AI audit round, requested files, and inspected-file counts for the run."
  ];
}

function renderAdditionalSastFindings(scannerResults: Row[], codeFindings: Row[], falsePositives: Row[], maxItems = 100): string[] {
  const represented = new Set([...codeFindings, ...falsePositives].map((finding) => `${finding.path ?? ""}:${finding.start_line ?? ""}`));
  const rows = scannerResults
    .filter((item) => !isDependencyVulnerabilityResult(item))
    .filter((item) => item.scanner !== "quality")
    .filter((item) => !represented.has(`${item.path ?? ""}:${item.start_line ?? ""}`))
    .sort((a, b) => scannerSortWeight(a) - scannerSortWeight(b));
  if (!rows.length) return ["No additional SAST findings outside promoted code findings."];
  const grouped = groupAdditionalRows(rows);
  const limited = grouped.slice(0, maxItems);
  const lines = [
    "| Severity | Rule | Category | Count | Reason | Primary file | Examples |",
    "|---|---|---|---:|---|---|---|"
  ];
  for (const group of limited) {
    const item = group.rows[0];
    const examples = group.rows.slice(0, 3).map((row) => `${row.path ?? "unknown"}:${row.start_line ?? "?"}`).join("<br>");
    lines.push([
      tableCell(item.severity),
      tableCell(`${item.scanner}/${item.rule_id}`),
      tableCell(item.category ?? "security"),
      String(group.rows.length),
      tableCell(firstSentence(item.title || item.message, 180)),
      tableCell(`${item.path ?? "unknown"}:${item.start_line ?? "?"}`),
      tableCell(examples)
    ].join(" | ").replace(/^/, "| ").replace(/$/, " |"));
  }
  if (grouped.length > limited.length) lines.push(`- Omitted ${grouped.length - limited.length} additional grouped SAST findings from report view.`);
  return lines;
}

function tableCell(value: unknown): string {
  return escapeHtml(String(value ?? ""))
    .replaceAll("|", "\\|")
    .replace(/\r?\n/g, "<br>")
    .trim() || "unknown";
}

function groupAdditionalRows(rows: Row[]): Array<{ key: string; rows: Row[] }> {
  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    const key = `${row.scanner}|${row.rule_id}|${row.severity}|${row.path ?? ""}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return [...groups.entries()].map(([key, groupedRows]) => ({ key, rows: groupedRows })).sort((a, b) => scannerSortWeight(a.rows[0]) - scannerSortWeight(b.rows[0]) || b.rows.length - a.rows.length);
}

function renderNoiseBucket(scannerResults: Row[]): string[] {
  const lowSignal = scannerResults.filter((item) => item.severity === "low" || item.scanner === "quality");
  if (!lowSignal.length) return ["No low-signal scanner noise recorded."];
  const groups = new Map<string, number>();
  for (const item of lowSignal) {
    const key = `${item.scanner}/${item.rule_id}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  return [...groups.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([key, count]) => `- ${escapeHtml(key)}: ${count}`);
}

function scannerSortWeight(item: Row): number {
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const scannerOrder: Record<string, number> = { "taint-flow": 0, "taint-lite": 1, "config-checks": 2, bearer: 3, semgrep: 4, gitleaks: 5, "custom-rules": 6 };
  return (severityOrder[item.severity] ?? 5) * 10 + (scannerOrder[item.scanner] ?? 9);
}

function bucketCodeFindings(findings: Row[]): { confirmed: Row[]; suspected: Row[]; needsDynamic: Row[] } {
  return {
    confirmed: findings.filter((item) => item.status === "confirmed" || item.status === "confirmed_true_positive"),
    suspected: findings.filter((item) => item.status === "suspected" || item.status === "likely_true_positive"),
    needsDynamic: findings.filter((item) => item.status === "needs_dynamic_test" || item.status === "security_hotspot" || item.status === "needs_context")
  };
}

function dedupeCodeFindings(findings: Row[]): Row[] {
  const seen = new Set<string>();
  return findings.filter((item) => {
    const key = [
      item.path ?? "unknown",
      normalizeCategory(item.category),
      normalizeTitle(item.title),
      item.start_line ?? ""
    ].join("|").toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderCodeFindings(findings: Row[], repoPath: string): string[] {
  if (!findings.length) return ["No findings in this bucket."];
  return findings.flatMap((item, index) => renderItemDetails(
    `${index + 1}. ${escapeHtml(item.severity)} ${escapeHtml(item.title)} @${escapeHtml(item.path ?? "unknown")}:${item.start_line ?? "?"}`,
    [
      `- Vulnerability type: ${escapeHtml(item.category)}`,
      `- Severity: ${escapeHtml(item.severity)}`,
      `- Confidence: ${escapeHtml(item.confidence)}`,
      `- Status: ${escapeHtml(item.status)}`,
      `- Baseline status: ${escapeHtml(item.baseline_status ?? "unknown")}`,
      `- Fingerprint: ${escapeHtml(item.fingerprint ?? "unknown")}`,
      `- Provenance: ${provenance(item)}`,
      ...ruleMetadataLines(item),
      `- Exploitability score: ${item.exploitability_score ?? scoreCodeExploitability(item)}/100`,
      `- Reachability: ${reachability(item)}`,
      `- Short description: ${firstSentence(item.reasoning, 220)}`,
      `- Why confidence is ${item.confidence}: ${confidenceReason(item)}`,
      "",
      "### Description",
      cleanParagraph(item.reasoning),
      "",
      "### Source-to-Sink Trace",
      `- Source: ${cleanParagraph(item.source ?? "unknown input/source")}`,
      `- Sink: ${cleanParagraph(item.sink ?? "reported vulnerable operation")}`,
      `- Location: \`${escapeHtml(item.path ?? "unknown")}:${item.start_line ?? "?"}\``,
      "",
      "### Evidence Snippet",
      ...renderSnippet(repoPath, item),
      "",
      "### Steps to Reproduce",
      ...reproductionSteps(item),
      "",
      "### Dynamic Validation Plan",
      ...dynamicValidationPlan(item),
      "",
      "### How to Fix",
      cleanParagraph(item.remediation),
      "",
      "### Suggested Patch Direction",
      patchDirection(item)
    ],
    index === 0 && ["critical", "high"].includes(String(item.severity))
  ));
}

function ruleMetadataLines(item: Row): string[] {
  const raw = parseRaw(item.raw_json);
  const rule = raw.rule ?? raw;
  const lines: string[] = [];
  if (rule.cwe) lines.push(`- CWE: ${escapeHtml(rule.cwe)}`);
  if (rule.owasp) lines.push(`- OWASP: ${escapeHtml(rule.owasp)}`);
  if (Array.isArray(rule.references) && rule.references.length) lines.push(`- References: ${rule.references.slice(0, 2).map((ref: string) => escapeHtml(ref)).join(", ")}`);
  return lines;
}

function renderFalsePositive(item: Row, index: number): string[] {
  return renderItemDetails(`${index}. ${escapeHtml(item.title)} @${escapeHtml(item.path ?? "unknown")}:${item.start_line ?? "?"}`, [
    `- Original severity: ${escapeHtml(item.severity)}`,
    `- Reason: ${cleanParagraph(item.reasoning)}`,
    `- Recommendation: ${cleanParagraph(item.remediation)}`
  ]);
}

interface DependencyFinding {
  packageName: string;
  cves: string[];
  severity: string;
  titles: string[];
  direct: boolean;
  packagePath: string;
  used: boolean;
  usageEvidence: string[];
  reachability: string;
  probability: number;
  fix: string;
  sources: Row[];
}

function buildDependencyFindings(repoPath: string, results: Row[]): DependencyFinding[] {
  const groups = new Map<string, Row[]>();
  for (const result of results) {
    const raw = parseRaw(result.raw_json);
    const packageName = dependencyPackageName(raw, result);
    groups.set(packageName, [...(groups.get(packageName) ?? []), result]);
  }
  return [...groups.values()].map((items) => {
    const first = items[0];
    const raw = parseRaw(first.raw_json);
    const packageName = dependencyPackageName(raw, first);
    const cves = [...new Set(items.map((item) => item.rule_id).filter(Boolean))];
    const direct = isDirectDependency(repoPath, packageName);
    const usageEvidence = findDependencyUsage(repoPath, packageName);
    const used = usageEvidence.length > 0;
    const severity = maxSeverity(items.map((item) => item.severity));
    return {
      packageName,
      cves,
      severity,
      titles: [...new Set(items.map((item) => cleanParagraph(item.title)).filter(Boolean))],
      direct,
      packagePath: dependencyPackagePath(repoPath, packageName, direct),
      used,
      usageEvidence,
      reachability: dependencyReachability(direct, used),
      probability: scoreDependencyExploitability(severity, direct, used),
      fix: dependencyFix(raw, packageName),
      sources: items
    };
  }).sort((a, b) => b.probability - a.probability);
}

function isDependencyVulnerabilityResult(item: Row): boolean {
  if (item.scanner !== "trivy" && item.scanner !== "osv-scanner") return false;
  const raw = parseRaw(item.raw_json);
  return Boolean(raw.VulnerabilityID || raw.id || /^CVE-\d{4}-\d+$/i.test(String(item.rule_id ?? "")) || /^GHSA-/i.test(String(item.rule_id ?? "")));
}

function dependencyPackageName(raw: Row, result: Row): string {
  const rawName = raw.PkgName ?? raw.package?.name ?? raw.Package?.Name ?? raw.name;
  if (rawName && rawName !== "unknown") return String(rawName).trim();
  const titlePrefix = String(result.title ?? "").split(":")[0]?.trim();
  return titlePrefix || "unknown";
}

function renderDependencyFinding(item: DependencyFinding, index: number): string[] {
  return renderItemDetails(`${index}. ${escapeHtml(item.severity)} ${escapeHtml(item.packageName)} (${escapeHtml(item.cves.join(", "))})`, [
    `- Severity: ${escapeHtml(item.severity)}`,
    `- Direct dependency: ${item.direct ? "yes" : "no, appears transitive"}`,
    `- Package path: ${escapeHtml(item.packagePath)}`,
    `- Used by codebase: ${item.used ? "yes" : "no usage found in indexed source"}`,
    `- Reachability: ${escapeHtml(item.reachability)}`,
    `- Exploitation probability: ${item.probability}/100`,
    `- Vulnerabilities: ${escapeHtml(item.titles.slice(0, 4).join("; "))}`,
    "",
    "#### Usage Evidence",
    ...(item.usageEvidence.length ? item.usageEvidence.map((evidence) => `- ${escapeHtml(evidence)}`) : ["- No direct import/require/reference found in application source files."]),
    "",
    "#### Fix",
    `- ${item.fix}`
  ], index === 1 && item.probability >= 70);
}

function dependencyReachability(direct: boolean, used: boolean): string {
  if (direct && used) return "reachable candidate: direct dependency is imported/referenced by application source";
  if (direct) return "installed directly, but no application source import/reference was found";
  if (used) return "transitive dependency appears referenced by application source; validate package path";
  return "transitive/unreferenced in indexed source; prioritize lower unless runtime evidence exists";
}

function parseRaw(rawJson: unknown): Row {
  if (!rawJson || typeof rawJson !== "string") return {};
  try {
    return JSON.parse(rawJson);
  } catch {
    return {};
  }
}

function isDirectDependency(repoPath: string, packageName: string): boolean {
  const packageJson = path.join(repoPath, "package.json");
  try {
    if (fs.existsSync(packageJson)) {
      const parsed = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      return Boolean(parsed.dependencies?.[packageName] || parsed.devDependencies?.[packageName] || parsed.peerDependencies?.[packageName] || parsed.optionalDependencies?.[packageName]);
    }
    const composer = path.join(repoPath, "composer.json");
    if (fs.existsSync(composer)) {
      const parsed = JSON.parse(fs.readFileSync(composer, "utf8"));
      return Boolean(parsed.require?.[packageName] || parsed["require-dev"]?.[packageName]);
    }
    const gemfile = path.join(repoPath, "Gemfile");
    if (fs.existsSync(gemfile)) return new RegExp(`gem\\s+['"]${escapeRegExp(packageName.split("/").pop() ?? packageName)}['"]`).test(fs.readFileSync(gemfile, "utf8"));
  } catch {
    return false;
  }
  return false;
}

function dependencyPackagePath(repoPath: string, packageName: string, direct: boolean): string {
  const packageLock = path.join(repoPath, "package-lock.json");
  if (direct) return `package.json -> ${packageName}`;
  if (!fs.existsSync(packageLock)) return `transitive dependency -> ${packageName}`;
  try {
    const parsed = JSON.parse(fs.readFileSync(packageLock, "utf8"));
    const key = `node_modules/${packageName}`;
    if (parsed.packages?.[key]) return `package-lock.json -> ${key}`;
  } catch {
    return `transitive dependency -> ${packageName}`;
  }
  return `transitive dependency -> ${packageName}`;
}

function findDependencyUsage(repoPath: string, packageName: string): string[] {
  if (!repoPath || packageName === "unknown") return [];
  const evidence: string[] = [];
  const packageRegex = escapeRegExp(packageName);
  const patterns = [
    new RegExp(`from\\s+['"]${packageRegex}['"]`),
    new RegExp(`import\\s+['"]${packageRegex}['"]`),
    new RegExp(`require\\(\\s*['"]${packageRegex}['"]\\s*\\)`),
    new RegExp(`(?:require|require_relative)\\s+['"]${packageRegex}['"]`),
    new RegExp(`(?:include|include_once|require|require_once)\\s*\\(?\\s*['"][^'"]*${packageRegex}[^'"]*['"]`),
    new RegExp(`use\\s+${packageRegex.replace(/\\\\\//g, "\\\\")}`),
    new RegExp(`\\b${packageRegex}\\b`)
  ];
  for (const file of walkSourceFiles(repoPath)) {
    const content = fs.readFileSync(file, "utf8");
    const lines = content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (patterns.some((pattern) => pattern.test(line))) {
        evidence.push(`${path.relative(repoPath, file).split(path.sep).join("/")}:${index + 1} - ${line.trim().slice(0, 160)}`);
        if (evidence.length >= 5) return evidence;
      }
    }
  }
  return evidence;
}

function walkSourceFiles(repoPath: string): string[] {
  const ignored = new Set([".git", "node_modules", "dist", "build", "coverage", ".next", ".nuxt", "vendor", ".codeguardian"]);
  const extensions = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".cs"]);
  const files: string[] = [];
  const stack = [repoPath];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ignored.has(entry.name)) continue;
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(absolute);
      else if (entry.isFile() && extensions.has(path.extname(entry.name)) && fs.statSync(absolute).size < 500_000) files.push(absolute);
    }
  }
  return files;
}

function scoreDependencyExploitability(severity: string, direct: boolean, used: boolean): number {
  const base = severity === "critical" ? 75 : severity === "high" ? 60 : severity === "medium" ? 40 : severity === "low" ? 20 : 10;
  const score = base + (direct ? 15 : -10) + (used ? 20 : -20);
  return Math.max(0, Math.min(100, score));
}

function normalizeCategory(category: unknown): string {
  const value = String(category ?? "security").toLowerCase();
  if (value === "secrets") return "secret";
  if (value.includes("crypto")) return "crypto";
  return value;
}

function normalizeTitle(title: unknown): string {
  return String(title ?? "").toLowerCase().replace(/detected|hardcoded|candidate|repository|file|exposed/g, "").replace(/[^a-z0-9]+/g, " ").trim();
}

function provenance(item: Row): string {
  const raw = String(item.raw_json ?? "");
  if (String(item.source ?? "").toLowerCase().includes("ai") || raw.includes("AI exploratory")) return "AI exploratory source audit";
  if (String(item.source ?? "").includes("semgrep")) return "Semgrep via Docker + AI triage";
  if (String(item.source ?? "").includes("trivy")) return "Trivy via Docker + AI triage";
  if (String(item.source ?? "").includes("bearer")) return "Bearer via Docker + AI triage";
  if (String(item.source ?? "").includes("custom-rules")) return "Custom deterministic rule + AI triage";
  return cleanParagraph(item.source ?? "AI/scanner triage");
}

function scoreCodeExploitability(item: Row): number {
  const severityBase: Record<string, number> = { critical: 85, high: 70, medium: 45, low: 20, info: 5 };
  const confidenceBonus: Record<string, number> = { confirmed: 15, high: 10, medium: 0, low: -15 };
  let score = (severityBase[item.severity] ?? 30) + (confidenceBonus[item.confidence] ?? 0);
  const text = `${item.title} ${item.category} ${item.reasoning} ${item.source} ${item.sink}`.toLowerCase();
  if (/authenticated|admin|owner/.test(text)) score -= 10;
  if (/csrf|xss|injection|secret|private key|crypto|ssrf/.test(text)) score += 8;
  if (item.status === "suspected") score -= 10;
  if (item.status === "needs_dynamic_test" || item.status === "security_hotspot" || item.status === "needs_context") score -= 5;
  if (item.status === "confirmed_true_positive") score += 8;
  if (item.status === "likely_true_positive") score += 3;
  return Math.max(0, Math.min(100, Math.round(score)));
}

function reachability(item: Row): string {
  const text = `${item.path} ${item.reasoning} ${item.source} ${item.sink}`.toLowerCase();
  if (/\.env|private key|secret/.test(text)) return "Reachable if repository, deployment bundle, or host filesystem is exposed.";
  if (/route|form|request|fetcher|webhook|api|action|loader/.test(text)) return "Likely reachable through application route or request handler.";
  if (/export|email|csv|shopify|product|database/.test(text)) return "Reachable through application workflow or stored data path.";
  return "Reachability needs manual validation.";
}

function confidenceReason(item: Row): string {
  if (item.confidence === "confirmed") return "AI/scanner evidence includes a concrete file, line, and source-to-sink explanation.";
  if (item.confidence === "high") return "Evidence is specific, but exploitability may depend on runtime configuration or caller context.";
  if (item.confidence === "medium") return "The pattern is plausible, but reachability or data control needs manual confirmation.";
  return "Evidence is weak or incomplete; treat as a validation task before fixing.";
}

function renderSnippet(repoPath: string, item: Row): string[] {
  if (!repoPath || !item.path || !item.start_line) return ["No snippet available."];
  const absolute = path.join(repoPath, item.path);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) return ["No snippet available."];
  if (/(^|\/)\.env($|\.|\/)/.test(item.path)) return ["```text", "[REDACTED ENV FILE CONTENT]", "```"];
  if (fs.statSync(absolute).size > 600_000) return ["Snippet omitted because file is large."];
  const lines = fs.readFileSync(absolute, "utf8").split(/\r?\n/);
  const start = Math.max(1, Number(item.start_line) - 4);
  const end = Math.min(lines.length, Number(item.end_line || item.start_line) + 4);
  const body = lines.slice(start - 1, end).map((line, offset) => `${String(start + offset).padStart(4, " ")} | ${escapeCodeFence(line)}`).join("\n");
  return ["```text", body, "```"];
}

function reproductionSteps(item: Row): string[] {
  const text = `${item.title} ${item.category} ${item.reasoning}`.toLowerCase();
  if (text.includes("csv")) {
    return [
      "1. Create or modify a product/feed field with a spreadsheet formula payload such as `=HYPERLINK(\"https://example.test\",\"click\")`.",
      "2. Export the affected CSV from the application.",
      "3. Open the CSV in spreadsheet software and confirm the field is interpreted as a formula."
    ];
  }
  if (text.includes("xss") || text.includes("html")) {
    return [
      "1. Insert an HTML payload such as `<img src=x onerror=alert(1)>` into the source field described above.",
      "2. Trigger the affected UI/email/rendering workflow.",
      "3. Confirm whether the payload is escaped or rendered as active HTML."
    ];
  }
  if (text.includes("csrf")) {
    return [
      "1. Log in as an authorized user in one browser tab.",
      "2. From another origin, submit a form POST to the affected action without a CSRF token.",
      "3. Confirm whether the state-changing action succeeds."
    ];
  }
  if (text.includes("ssrf")) {
    return [
      "1. Identify where the reported host/domain parameter is accepted.",
      "2. Supply a non-Shopify host or local network canary URL in a safe local environment.",
      "3. Confirm whether the server attempts the outbound request."
    ];
  }
  if (text.includes("json.parse")) {
    return [
      "1. Submit malformed or unexpected JSON to the reported form field.",
      "2. Include edge cases such as arrays, objects with `__proto__`, and oversized payloads.",
      "3. Confirm whether schema validation rejects the payload before application logic uses it."
    ];
  }
  if (text.includes("secret") || text.includes("private key")) {
    return [
      "1. Confirm the file exists in the repository or deployment artifact.",
      "2. Verify whether the value is real or a placeholder.",
      "3. Rotate the value if real, then remove it from version control."
    ];
  }
  return [
    `1. Open \`${item.path ?? "unknown"}\`${item.start_line ? ` around line ${item.start_line}` : ""}.`,
    `2. Trace \`${item.source ?? item.category}\` to \`${item.sink ?? "the reported sink"}\`.`,
    "3. Validate exploitability in a safe local environment."
  ];
}

function dynamicValidationPlan(item: Row): string[] {
  const text = `${item.title} ${item.category} ${item.reasoning}`.toLowerCase();
  if (item.status === "confirmed_true_positive") return ["- Already evidence-backed by static/AI verification. Add a regression test around the cited source-to-sink path."];
  if (text.includes("command")) return ["- In a local fixture only, replace shell sink with a spy/stub and assert attacker-controlled argument reaches it.", "- Do not execute attacker-controlled commands during validation."];
  if (text.includes("ssrf")) return ["- In a local fixture only, point outbound calls at a loopback canary server and assert whether untrusted URL/host is requested.", "- Block real external/internal network targets during validation."];
  if (text.includes("path") || text.includes("file")) return ["- In a temp directory fixture, try `../` traversal against the cited route/helper and assert reads stay inside the allowed base path."];
  if (text.includes("xss")) return ["- Render the cited path in a local browser/test renderer and assert payload is escaped, not executed."];
  if (text.includes("csrf")) return ["- Submit the cited state-changing request without token from a different origin in a local app instance and assert rejection."];
  return ["- Build a local regression test that exercises the cited source, sink, and missing control without touching external systems."];
}

function patchDirection(item: Row): string {
  const raw = parseRaw(item.raw_json);
  if (raw.rule?.fix) return cleanParagraph(raw.rule.fix);
  if (raw.fix) return cleanParagraph(raw.fix);
  const text = `${item.title} ${item.category} ${item.reasoning}`.toLowerCase();
  if (text.includes("csv")) return "Use a CSV library or central `escapeCsvCell()` helper that quotes every field, escapes quotes, and neutralizes cells beginning with `=`, `+`, `-`, or `@`.";
  if (text.includes("xss") || text.includes("html")) return "Add an HTML escaping/sanitization helper at the boundary where untrusted data enters templates, emails, or stored HTML fields.";
  if (text.includes("csrf")) return "Add CSRF token generation to loaders/session state and validate token equality in every state-changing action.";
  if (text.includes("ssrf")) return "Validate hostnames with an allowlist such as `/^[a-z0-9-]+\\.myshopify\\.com$/i` before constructing outbound URLs.";
  if (text.includes("json.parse")) return "Replace raw `JSON.parse` with schema validation using zod or equivalent, and reject unexpected keys/types before persistence.";
  if (text.includes("auth tag") || text.includes("gcm")) return "Pass `{ authTagLength: 16 }` to `createDecipheriv` and reject ciphertext whose tag length is not exactly 16 bytes.";
  if (text.includes("secret") || text.includes("private key")) return "Remove the committed file/value, add it to `.gitignore`, rotate any real secret, and load it from secure runtime config.";
  return "Apply the remediation above and add a regression test for the vulnerable path.";
}

function dependencyFix(raw: Row, packageName: string): string {
  const fixed = raw.FixedVersion || raw.fixed_version || raw.database_specific?.fixed_range;
  if (fixed) return `Upgrade \`${escapeHtml(packageName)}\` to a patched version: ${escapeHtml(String(fixed))}.`;
  return `Upgrade \`${escapeHtml(packageName)}\` to the latest patched version and regenerate the lockfile.`;
}

function maxSeverity(severities: string[]): string {
  const order = ["critical", "high", "medium", "low", "info"];
  return severities.sort((a, b) => order.indexOf(a) - order.indexOf(b))[0] ?? "info";
}

function firstSentence(text: unknown, maxLength: number): string {
  const normalized = cleanParagraph(text);
  const sentence = normalized.match(/^.*?[.!?](?:\s|$)/)?.[0] ?? normalized;
  return sentence.length > maxLength ? `${sentence.slice(0, maxLength - 3)}...` : sentence;
}

function cleanParagraph(text: unknown): string {
  return escapeHtml(String(text ?? "").replace(/\s+/g, " ").trim() || "No details provided.");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(value: string): string {
  return value.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function escapeCodeFence(value: string): string {
  return value.replaceAll("```", "``\\`");
}
