import path from "node:path";
import fs from "node:fs";
import { openDatabase } from "../db/database.js";
import { createScan, finishScan, getScanBundle, insertFinding, insertScannerResult } from "../db/repositories.js";
import { indexRepository } from "../repo/repoIndexer.js";
import { runCustomRules } from "../scanners/customRules.js";
import { runQualityChecks } from "../scanners/quality.js";
import { runSemgrep } from "../scanners/semgrep.js";
import { runGitleaks } from "../scanners/gitleaks.js";
import { runTrivy } from "../scanners/trivy.js";
import { runOsv } from "../scanners/osv.js";
import { runBearer } from "../scanners/bearer.js";
import { deterministicFinding, aiTriage } from "../ai/triage.js";
import { runExploratoryAudit } from "../ai/audit.js";
import { createAiProvider } from "../ai/provider.js";
import { buildContextPack } from "../repo/contextPackBuilder.js";
import { writeJsonReport } from "../reports/json.js";
import { writeMarkdownReport } from "../reports/markdown.js";
import { writeSarifReport } from "../reports/sarif.js";
import type { RunContext } from "./runContext.js";
import { DEFAULT_DB_PATH, SEVERITY_ORDER } from "../config/defaults.js";
import { checkTool } from "../tools/commandRunner.js";

export async function runScan(ctx: RunContext): Promise<{ scanId: string; reportFiles: string[]; warnings: string[]; exitCode: number }> {
  const db = openDatabase(path.resolve(ctx.repoPath, ctx.env.CODEGUARDIAN_DB_PATH || DEFAULT_DB_PATH));
  let aiMeta: { provider?: string; model?: string } = {};
  let aiProvider;
  if (ctx.options.ai) {
    ctx.logger.info("ai: loading provider config");
    const created = createAiProvider(ctx.env, ctx.options.provider, ctx.options.model);
    aiProvider = created.provider;
    aiMeta = { provider: created.provider.name, model: created.model };
    ctx.logger.info(`ai: provider=${aiMeta.provider} model=${aiMeta.model}`);
  }
  ctx.logger.info("db: opening scan database");
  const scanId = createScan(db, ctx.repoPath, ctx.options, aiMeta.provider, aiMeta.model);
  ctx.logger.info(`scan: created ${scanId}`);
  const warnings: string[] = [];
  ctx.logger.info("tools: checking availability");
  const toolStatuses = await Promise.all(["docker", "rg", "node", "npm"].map(async (name) => ({ name, ...(await checkTool(name)) })));
  for (const tool of toolStatuses) ctx.logger.info(`tools: ${tool.name} ${tool.available ? "available" : "missing"}`);
  try {
    ctx.logger.info("indexing repository");
    const files = indexRepository(db, scanId, ctx.repoPath, {
      maxFiles: ctx.options.maxFiles,
      maxFileSize: ctx.options.maxFileSize,
      include: ctx.options.include,
      exclude: ctx.options.exclude
    });
    ctx.logger.info(`index: indexed ${files.length} files`);
    ctx.logger.info("scanners: running custom rules");
    const customResults = runCustomRules(files);
    ctx.logger.info(`scanners: custom rules produced ${customResults.length} results`);
    ctx.logger.info("scanners: running quality checks");
    const qualityResults = runQualityChecks(files);
    ctx.logger.info(`scanners: quality checks produced ${qualityResults.length} results`);
    ctx.logger.info("scanners: running external scanners");
    const scannerJobs = [
      runLoggedScanner(ctx, "semgrep", () => runSemgrep(ctx.repoPath)),
      runLoggedScanner(ctx, "gitleaks", () => runGitleaks(ctx.repoPath)),
      runLoggedScanner(ctx, "trivy", () => runTrivy(ctx.repoPath)),
      runLoggedScanner(ctx, "osv-scanner", () => runOsv(ctx.repoPath)),
      runLoggedScanner(ctx, "bearer", () => runBearer(ctx.repoPath))
    ];
    const scanners = await Promise.all(scannerJobs);
    const scannerResults = [
      ...customResults,
      ...qualityResults,
      ...scanners.flatMap((scan) => {
        if (scan.warning) warnings.push(scan.warning);
        return scan.results;
      })
    ];
    ctx.logger.info(`scanners: total ${scannerResults.length} results`);
    ctx.logger.info("db: storing scanner results");
    for (const result of scannerResults) insertScannerResult(db, scanId, result);
    const highSignal = scannerResults.filter((result) => ["critical", "high", "medium"].includes(result.severity)).slice(0, ctx.options.maxAiFindings);
    ctx.logger.info(`triage: selected ${highSignal.length} high-signal results max=${ctx.options.maxAiFindings}`);
    ctx.logger.info("context: building AI context packs");
    const contextPacks = highSignal.map((result, index) => {
      ctx.logger.info(`context: pack ${index + 1}/${highSignal.length} ${result.scanner}/${result.ruleId} ${result.path ?? ""}:${result.startLine ?? ""}`);
      return buildContextPack(result, files, scannerResults, ctx.env.CODEGUARDIAN_MAX_CONTEXT_CHARS);
    });
    const findings = aiProvider
      ? await aiTriage(aiProvider, contextPacks, (message) => ctx.logger.info(message))
      : scannerResults.map(deterministicFinding);
    if (aiProvider && ctx.options.aiAudit) {
      ctx.logger.info(`ai-audit: enabled maxFiles=${ctx.options.maxAiAuditFiles} maxRounds=${ctx.options.maxAiAuditRounds} maxChars=${ctx.options.maxAiAuditChars}`);
      const auditFindings = await runExploratoryAudit(aiProvider, files, scannerResults, {
        maxFiles: ctx.options.maxAiAuditFiles,
        maxRounds: ctx.options.maxAiAuditRounds,
        maxChars: ctx.options.maxAiAuditChars
      }, (message) => ctx.logger.info(message));
      findings.push(...auditFindings);
      ctx.logger.info(`ai-audit: added ${auditFindings.length} findings`);
    } else if (aiProvider) {
      ctx.logger.info("ai-audit: disabled");
    }
    ctx.logger.info(`triage: produced ${findings.length} findings`);
    ctx.logger.info("db: storing findings");
    for (const finding of findings) insertFinding(db, scanId, finding);
    ctx.logger.info("db: marking scan completed");
    finishScan(db, scanId, "completed");
    const bundle = { ...getScanBundle(db, scanId), toolStatuses };
    ctx.logger.info(`reports: writing format=${ctx.options.format} out=${ctx.outDir}`);
    const reportFiles = writeReports(ctx.outDir, ctx.options.format, bundle, warnings);
    for (const file of reportFiles) ctx.logger.info(`reports: wrote ${file}`);
    return { scanId, reportFiles, warnings, exitCode: failExitCode(findings, ctx.options.failOn) };
  } catch (error) {
    ctx.logger.error(`scan failed: ${error instanceof Error ? error.message : String(error)}`);
    finishScan(db, scanId, "failed");
    throw error;
  } finally {
    ctx.logger.info("db: closing database");
    db.close();
  }
}

async function runLoggedScanner(ctx: RunContext, name: string, run: () => Promise<{ results: unknown[]; warning?: string }>): Promise<{ results: any[]; warning?: string }> {
  const start = Date.now();
  ctx.logger.info(`scanner:${name}: start`);
  const result = await run();
  const seconds = ((Date.now() - start) / 1000).toFixed(1);
  ctx.logger.info(`scanner:${name}: done results=${result.results.length} elapsed=${seconds}s${result.warning ? " warning=yes" : ""}`);
  if (result.warning) ctx.logger.warn(`scanner:${name}: ${result.warning.split(/\r?\n/)[0]}`);
  return result as { results: any[]; warning?: string };
}

export function writeReports(outDir: string, format: string, bundle: unknown, warnings: string[]): string[] {
  const reportBase = buildReportBase(bundle);
  cleanupUnrequestedReports(outDir, format);
  const files: string[] = [];
  if (format === "json" || format === "all") files.push(writeJsonReport(outDir, bundle, reportBase));
  if (format === "markdown" || format === "all") files.push(writeMarkdownReport(outDir, bundle, warnings, reportBase));
  if (format === "sarif" || format === "all") files.push(writeSarifReport(outDir, bundle, reportBase));
  return files;
}

function cleanupUnrequestedReports(outDir: string, format: string): void {
  if (format === "all") return;
  const keepExt = format === "markdown" ? ".md" : format === "json" ? ".json" : format === "sarif" ? ".sarif" : "";
  if (!fs.existsSync(outDir)) return;
  for (const entry of fs.readdirSync(outDir)) {
    if (!entry.startsWith("report")) continue;
    if (path.extname(entry) !== keepExt) fs.rmSync(path.join(outDir, entry));
  }
}

function buildReportBase(bundle: unknown): string {
  const repoPath = typeof bundle === "object" && bundle && "scan" in bundle ? (bundle as any).scan?.repo_path : undefined;
  const appName = sanitizeReportPart(path.basename(String(repoPath || "codebase")) || "codebase");
  return `report-${appName}-${formatReportTimestamp(new Date())}`;
}

function formatReportTimestamp(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function sanitizeReportPart(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "codebase";
}

function failExitCode(findings: Array<{ severity: string }>, failOn: string): number {
  if (failOn === "none") return 0;
  const threshold = SEVERITY_ORDER.indexOf(failOn as any);
  return findings.some((finding) => SEVERITY_ORDER.indexOf(finding.severity as any) <= threshold) ? 2 : 0;
}
