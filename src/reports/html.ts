import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

type Row = Record<string, any>;

export function writeHtmlReport(outDir: string, bundle: any, warnings: string[] = [], reportBase = "report"): string {
  ensureDir(outDir);
  const repoPath = String(bundle.scan?.repo_path ?? "");
  const findings = bundle.findings ?? [];
  const scanner = bundle.scannerResults ?? [];
  const codeFindings = findings.filter((item: Row) => item.category !== "dependency");
  const activeFindings = codeFindings.filter((item: Row) => item.status !== "false_positive");
  const falsePositives = codeFindings.filter((item: Row) => item.status === "false_positive");
  const dependencies = scanner.filter(isDependencyVulnerabilityResult);
  const compliance = scanner.filter((item: Row) => item.scanner === "compliance");
  const attackChains = scanner.filter((item: Row) => item.scanner === "correlation");
  const additionalSast = additionalSastRows(scanner, activeFindings, falsePositives);
  const html = renderDocument({
    repoPath,
    scan: bundle.scan ?? {},
    activeFindings,
    falsePositives,
    dependencies,
    compliance,
    attackChains,
    additionalSast,
    scanner,
    files: bundle.files ?? [],
    aiUsage: bundle.aiUsage ?? [],
    warnings
  });
  const file = path.join(outDir, `${reportBase}.html`);
  fs.writeFileSync(file, html);
  return file;
}

function renderDocument(input: {
  repoPath: string;
  scan: Row;
  activeFindings: Row[];
  falsePositives: Row[];
  dependencies: Row[];
  compliance: Row[];
  attackChains: Row[];
  additionalSast: Row[];
  scanner: Row[];
  files: Row[];
  aiUsage: Row[];
  warnings: string[];
}): string {
  const severityCounts = countBy(input.activeFindings, "severity");
  const aiRequests = input.aiUsage.reduce((sum, row) => sum + Number(row.requests ?? 0), 0);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codeguardian Security Report</title>
  <style>
    :root { color-scheme: light dark; --bg:#0f172a; --panel:#111827; --muted:#94a3b8; --text:#e5e7eb; --line:#334155; --accent:#38bdf8; --high:#fb7185; --med:#fbbf24; --low:#60a5fa; --ok:#34d399; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--text); }
    header { padding:24px 32px; border-bottom:1px solid var(--line); background:rgba(15,23,42,.96); backdrop-filter: blur(8px); }
    h1 { margin:0 0 10px; font-size:24px; }
    h2 { margin:0; font-size:18px; }
    main { padding:24px 32px 48px; max-width:1500px; margin:0 auto; }
    .toolbar { display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin-top:14px; }
    input, select { background:#020617; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:8px 10px; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:18px 0; }
    .metric, details { background:var(--panel); border:1px solid var(--line); border-radius:8px; }
    .metric { padding:14px; }
    .metric strong { display:block; font-size:26px; }
    details { margin:16px 0; overflow:hidden; }
    summary { cursor:pointer; padding:14px 16px; font-weight:700; border-bottom:1px solid var(--line); }
    details:not([open]) summary { border-bottom:0; }
    .section-body { padding:16px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:9px 8px; }
    th { color:#cbd5e1; background:var(--panel); }
    .card { border:1px solid var(--line); border-radius:8px; padding:14px; margin:12px 0; background:#0b1220; }
    .meta { color:var(--muted); font-size:12px; display:flex; gap:10px; flex-wrap:wrap; }
    .badge { border-radius:999px; padding:2px 8px; font-size:12px; border:1px solid var(--line); }
    .critical,.high { color:var(--high); } .medium { color:var(--med); } .low,.info { color:var(--low); } .confirmed_true_positive,.confirmed { color:var(--ok); }
    pre { overflow:auto; background:#020617; border:1px solid var(--line); border-radius:6px; padding:12px; }
    a { color:var(--accent); }
    .hidden { display:none !important; }
  </style>
</head>
<body>
  <header>
    <h1>Codeguardian Security Report</h1>
    <div class="meta">
      <span>Scan: ${esc(input.scan.id ?? "unknown")}</span>
      <span>Repo: ${esc(input.repoPath || "unknown")}</span>
      <span>Status: ${esc(input.scan.status ?? "unknown")}</span>
    </div>
    <div class="toolbar">
      <input id="search" type="search" placeholder="Search title, path, rule, reason">
      <select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
      <select id="status"><option value="">All statuses</option><option>confirmed_true_positive</option><option>likely_true_positive</option><option>security_hotspot</option><option>needs_context</option><option>suspected</option><option>false_positive</option><option>pass</option><option>fail</option><option>unknown</option></select>
    </div>
  </header>
  <main>
    <div class="grid">
      ${metric("Code Findings", input.activeFindings.length)}
      ${metric("Critical/High", (severityCounts.critical ?? 0) + (severityCounts.high ?? 0))}
      ${metric("Additional SAST", input.additionalSast.length)}
      ${metric("Dependencies", input.dependencies.length)}
      ${metric("Attack Chains", input.attackChains.length)}
      ${metric("Compliance", input.compliance.length)}
      ${metric("False Positives", input.falsePositives.length)}
      ${metric("Indexed Files", input.files.filter((file) => file.indexed).length)}
      ${metric("AI Requests", aiRequests)}
    </div>
    ${section("Fix First", renderFixFirst(input.activeFindings), true)}
    ${section("Attack Chains", renderAttackChainTable(input.attackChains), true)}
    ${section("Code Findings", renderFindings(input.repoPath, input.activeFindings), true)}
    ${section("Additional SAST Findings", renderAdditionalSastTable(input.additionalSast), false)}
    ${section("Dependency Findings", renderDependencyTable(input.dependencies), false)}
    ${section("Compliance Evidence", renderComplianceTable(input.compliance), false)}
    ${section("AI False Positives", renderFindings(input.repoPath, input.falsePositives), false)}
    ${section("Scanner Counts", renderScannerCounts(input.scanner), false)}
    ${section("AI Usage", renderAiUsageTable(input.aiUsage), false)}
    ${section("Warnings", input.warnings.length ? `<ul>${input.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : "<p>None</p>", false)}
  </main>
  <script>
    const search = document.querySelector('#search');
    const severity = document.querySelector('#severity');
    const status = document.querySelector('#status');
    function applyFilters() {
      const q = search.value.toLowerCase();
      const sev = severity.value;
      const stat = status.value;
      document.querySelectorAll('[data-row]').forEach((el) => {
        const text = el.textContent.toLowerCase();
        const ok = (!q || text.includes(q)) && (!sev || el.dataset.severity === sev) && (!stat || el.dataset.status === stat);
        el.classList.toggle('hidden', !ok);
      });
    }
    [search, severity, status].forEach((el) => el.addEventListener('input', applyFilters));
  </script>
</body>
</html>`;
}

function metric(label: string, value: unknown): string {
  return `<div class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`;
}

function section(title: string, body: string, open: boolean): string {
  return `<details${open ? " open" : ""}><summary>${esc(title)}</summary><div class="section-body">${body}</div></details>`;
}

function renderFixFirst(findings: Row[]): string {
  const top = findings
    .slice()
    .sort((a, b) => scoreFinding(b) - scoreFinding(a))
    .slice(0, 10);
  if (!top.length) return "<p>No high-priority fixes identified.</p>";
  return `<table><thead><tr><th>Score</th><th>Severity</th><th>Status</th><th>Finding</th><th>File</th></tr></thead><tbody>${top.map((item) => row(item, [
    scoreFinding(item),
    item.severity,
    item.status,
    item.title,
    `${item.path ?? "unknown"}:${item.start_line ?? "?"}`
  ])).join("")}</tbody></table>`;
}

function renderFindings(repoPath: string, findings: Row[]): string {
  if (!findings.length) return "<p>No findings.</p>";
  return findings.map((item, index) => `<article class="card" data-row data-severity="${escAttr(item.severity)}" data-status="${escAttr(item.status)}">
    <h3>${index + 1}. <span class="${escAttr(item.severity)}">${esc(item.severity)}</span> ${esc(item.title)}</h3>
    <div class="meta">
      <span class="badge ${escAttr(item.status)}">${esc(item.status)}</span>
      <span>${esc(item.category)}</span>
      <span>${esc(item.path ?? "unknown")}:${esc(item.start_line ?? "?")}</span>
      <span>confidence ${esc(item.confidence ?? "unknown")}</span>
    </div>
    <p>${esc(firstSentence(item.reasoning, 320))}</p>
    <details><summary>Details</summary>
      <p><strong>Source:</strong> ${esc(item.source ?? "unknown")}</p>
      <p><strong>Sink:</strong> ${esc(item.sink ?? "unknown")}</p>
      <p><strong>Remediation:</strong> ${esc(item.remediation ?? "Review and fix affected code.")}</p>
      ${renderSnippet(repoPath, item)}
    </details>
  </article>`).join("");
}

function renderAdditionalSastTable(rows: Row[]): string {
  if (!rows.length) return "<p>No additional SAST findings outside promoted code findings.</p>";
  return `<table><thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Reason</th><th>File</th><th>Scanner</th></tr></thead><tbody>${rows.map((item) => row(item, [
    item.severity,
    `${item.scanner}/${item.rule_id}`,
    item.category ?? "security",
    firstSentence(item.title || item.message, 220),
    `${item.path ?? "unknown"}:${item.start_line ?? "?"}`,
    item.scanner
  ])).join("")}</tbody></table>`;
}

function renderDependencyTable(rows: Row[]): string {
  if (!rows.length) return "<p>No dependency findings.</p>";
  return `<table><thead><tr><th>Severity</th><th>Package</th><th>Rule/CVE</th><th>Reason</th><th>File</th></tr></thead><tbody>${rows.map((item) => row(item, [
    item.severity,
    dependencyPackageName(parseRaw(item.raw_json), item),
    item.rule_id,
    firstSentence(item.title || item.message, 220),
    `${item.path ?? "unknown"}:${item.start_line ?? "?"}`
  ])).join("")}</tbody></table>`;
}

function renderComplianceTable(rows: Row[]): string {
  if (!rows.length) return "<p>No compliance evidence rows recorded.</p>";
  return `<table><thead><tr><th>Status</th><th>Control</th><th>Frameworks</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>${rows.map((item) => {
    const raw = parseRaw(item.raw_json);
    const evidence = Array.isArray(raw.evidence) && raw.evidence.length
      ? raw.evidence.slice(0, 3).map((entry: Row) => `${entry.path ?? "repo"}:${entry.line ?? "?"} ${entry.note ?? ""}`).join("\n")
      : "No evidence found in indexed files.";
    return row({ ...item, status: raw.status ?? "unknown" }, [
      raw.status ?? "unknown",
      `${item.rule_id}: ${String(item.title ?? "").replace(/^(PASS|FAIL|UNKNOWN):\s*/i, "")}`,
      [...(raw.controlIds ?? []), ...(raw.frameworks ?? [])].join(", "),
      evidence,
      raw.remediation ?? item.message
    ]);
  }).join("")}</tbody></table>`;
}

function renderAttackChainTable(rows: Row[]): string {
  if (!rows.length) return "<p>No attack-chain correlations recorded.</p>";
  return `<table><thead><tr><th>Severity</th><th>Chain</th><th>Impact</th><th>Evidence</th><th>Safe validation</th></tr></thead><tbody>${rows.map((item) => {
    const raw = parseRaw(item.raw_json);
    const chain = raw.attackChain ?? {};
    const evidence = Array.isArray(raw.evidence) && raw.evidence.length
      ? raw.evidence.slice(0, 3).map((entry: Row) => `${entry.path ?? "repo"}:${entry.line ?? "?"} ${entry.note ?? ""}`).join("\n")
      : item.message;
    const validation = Array.isArray(chain.validation) && chain.validation.length ? chain.validation.slice(0, 3).join("\n") : "Review related findings together in a safe local environment.";
    return row(item, [
      item.severity,
      `${item.rule_id}: ${item.title}`,
      chain.impact ?? item.message,
      evidence,
      validation
    ]);
  }).join("")}</tbody></table>`;
}

function renderScannerCounts(rows: Row[]): string {
  const counts = countBy(rows, "scanner");
  return `<table><thead><tr><th>Scanner</th><th>Count</th></tr></thead><tbody>${Object.entries(counts).map(([name, count]) => `<tr><td>${esc(name)}</td><td>${count}</td></tr>`).join("")}</tbody></table>`;
}

function renderAiUsageTable(rows: Row[]): string {
  if (!rows.length) return "<p>Token usage was not reported by the provider.</p>";
  return `<table><thead><tr><th>Tier</th><th>Provider</th><th>Model</th><th>Requests</th><th>Input tokens</th><th>Cached input tokens</th><th>Output tokens</th><th>Total tokens</th><th>Input cost USD</th><th>Cached input cost USD</th><th>Output cost USD</th><th>Total cost USD</th></tr></thead><tbody>${rows.map((item) => `<tr data-row><td>${esc(item.tier)}</td><td>${esc(item.provider)}</td><td>${esc(item.model)}</td><td>${esc(formatInteger(item.requests))}</td><td>${esc(formatInteger(item.inputTokens))}</td><td>${esc(formatInteger(item.cachedInputTokens))}</td><td>${esc(formatInteger(item.outputTokens))}</td><td>${esc(formatInteger(item.totalTokens))}</td><td>${esc(formatCost(item.inputCostUsd))}</td><td>${esc(formatCost(item.cachedInputCostUsd))}</td><td>${esc(formatCost(item.outputCostUsd))}</td><td>${esc(formatCost(item.costUsd))}</td></tr>`).join("")}</tbody></table>`;
}

function formatInteger(value: unknown): string {
  const number = Number(value ?? 0);
  return Number.isFinite(number) ? String(Math.round(number)) : "0";
}

function formatCost(value: unknown): string {
  if (value === null || value === undefined || value === "") return "not reported";
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(6) : "not reported";
}

function row(item: Row, cells: unknown[]): string {
  return `<tr data-row data-severity="${escAttr(item.severity)}" data-status="${escAttr(item.status ?? "")}">${cells.map((cell) => `<td>${esc(cell)}</td>`).join("")}</tr>`;
}

function additionalSastRows(scannerResults: Row[], codeFindings: Row[], falsePositives: Row[]): Row[] {
  const represented = new Set([...codeFindings, ...falsePositives].map((finding) => `${finding.path ?? ""}:${finding.start_line ?? ""}`));
  return scannerResults
    .filter((item) => !isDependencyVulnerabilityResult(item))
    .filter((item) => item.scanner !== "correlation")
    .filter((item) => item.scanner !== "compliance")
    .filter((item) => item.scanner !== "quality")
    .filter((item) => !represented.has(`${item.path ?? ""}:${item.start_line ?? ""}`))
    .sort((a, b) => scoreSeverity(a.severity) - scoreSeverity(b.severity))
    .slice(0, 500);
}

function renderSnippet(repoPath: string, item: Row): string {
  if (!repoPath || !item.path || !item.start_line) return "";
  const absolute = path.join(repoPath, item.path);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile() || fs.statSync(absolute).size > 600_000) return "";
  if (/(^|\/)\.env($|\.|\/)/.test(item.path)) return "<pre>[REDACTED ENV FILE CONTENT]</pre>";
  const lines = fs.readFileSync(absolute, "utf8").split(/\r?\n/);
  const start = Math.max(1, Number(item.start_line) - 4);
  const end = Math.min(lines.length, Number(item.end_line || item.start_line) + 4);
  const body = lines.slice(start - 1, end).map((line, offset) => `${String(start + offset).padStart(4, " ")} | ${line}`).join("\n");
  return `<pre>${esc(body)}</pre>`;
}

function isDependencyVulnerabilityResult(item: Row): boolean {
  if (item.scanner !== "trivy" && item.scanner !== "osv-scanner") return false;
  const raw = parseRaw(item.raw_json);
  return Boolean(raw.VulnerabilityID || raw.id || /^CVE-\d{4}-\d+$/i.test(String(item.rule_id ?? "")) || /^GHSA-/i.test(String(item.rule_id ?? "")));
}

function dependencyPackageName(raw: Row, result: Row): string {
  const rawName = raw.PkgName ?? raw.package?.name ?? raw.Package?.Name ?? raw.name;
  if (rawName && rawName !== "unknown") return String(rawName).trim();
  return String(result.title ?? "").split(":")[0]?.trim() || "unknown";
}

function scoreFinding(item: Row): number {
  return scoreSeverity(item.severity) * -20 + (item.status === "confirmed_true_positive" ? 20 : item.status === "likely_true_positive" ? 10 : 0);
}

function scoreSeverity(severity: unknown): number {
  return ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 } as Record<string, number>)[String(severity)] ?? 5;
}

function countBy(rows: Row[], key: string): Record<string, number> {
  return rows.reduce((acc, row) => {
    const value = String(row[key] ?? "unknown");
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function parseRaw(rawJson: unknown): Row {
  if (!rawJson || typeof rawJson !== "string") return {};
  try { return JSON.parse(rawJson); } catch { return {}; }
}

function firstSentence(text: unknown, maxLength: number): string {
  const normalized = String(text ?? "").replace(/\s+/g, " ").trim() || "No details provided.";
  const sentence = normalized.match(/^.*?[.!?](?:\s|$)/)?.[0] ?? normalized;
  return sentence.length > maxLength ? `${sentence.slice(0, maxLength - 3)}...` : sentence;
}

function esc(value: unknown): string {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function escAttr(value: unknown): string {
  return esc(value).replaceAll("'", "&#39;");
}
