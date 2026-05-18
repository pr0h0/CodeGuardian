import path from "node:path";
import fs from "node:fs";
import { openDatabase } from "../db/database.js";
import { createScan, finishScan, getScanBundle, insertFinding, insertScannerResult, insertScannerRun, upsertScanCache } from "../db/repositories.js";
import { indexRepository } from "../repo/repoIndexer.js";
import { runCustomRules } from "../scanners/customRules.js";
import { runQualityChecks } from "../scanners/quality.js";
import { runSemgrep } from "../scanners/semgrep.js";
import { runGitleaks } from "../scanners/gitleaks.js";
import { runTrivy } from "../scanners/trivy.js";
import { runOsv } from "../scanners/osv.js";
import { runBearer } from "../scanners/bearer.js";
import { runTaintLite } from "../scanners/taintLite.js";
import { runTaintFlow } from "../scanners/taintFlow.js";
import { runConfigChecks } from "../scanners/configChecks.js";
import { runComplianceChecks } from "../scanners/compliance.js";
import { runCorrelationChecks } from "../scanners/correlations.js";
import { applySuppressions } from "../scanners/suppressions.js";
import { deterministicFinding, aiTriage } from "../ai/triage.js";
import { runExploratoryAudit } from "../ai/audit.js";
import { aiHighModel, aiLowModel, aiMediumModel, createAiProvider } from "../ai/provider.js";
import type { AiProvider } from "../ai/types.js";
import { AiUsageTracker, type AiTier, withUsageTracking } from "../ai/usage.js";
import { buildContextPack } from "../repo/contextPackBuilder.js";
import { loadAiInstructions } from "../repo/aiInstructions.js";
import type { IndexedFile } from "../repo/repoIndexer.js";
import { writeJsonReport } from "../reports/json.js";
import { writeMarkdownReport } from "../reports/markdown.js";
import { writeSarifReport } from "../reports/sarif.js";
import { writeHtmlReport } from "../reports/html.js";
import { writeRuleExport } from "../reports/ruleExport.js";
import type { RunContext } from "./runContext.js";
import { DEFAULT_DB_PATH, SEVERITY_ORDER } from "../config/defaults.js";
import { checkTool } from "../tools/commandRunner.js";
import { buildBaselineDiff } from "./baseline.js";
import { attachFindingFingerprints, attachScannerFingerprints } from "./fingerprint.js";
import { ruleAllowedByProfile } from "../config/projectConfig.js";
import { planAiTriageCandidates, scoreScannerResult } from "./triagePlanner.js";
import { scannerImages } from "../scanners/dockerFallback.js";
import type { ScannerResult, Finding } from "../scanners/types.js";
import { sha256 } from "../utils/hashing.js";
import { lineSlice } from "../utils/lineMap.js";
import { redactSecrets } from "../utils/redact.js";
import { execSync } from "node:child_process";

type AiProviderSet = Record<AiTier, AiProvider> & { critic?: AiProvider };

export async function runScan(ctx: RunContext): Promise<{ scanId: string; reportFiles: string[]; warnings: string[]; exitCode: number }> {
  const db = openDatabase(path.resolve(ctx.repoPath, ctx.env.CODEGUARDIAN_DB_PATH || DEFAULT_DB_PATH));
  let aiMeta: { provider?: string; model?: string } = {};
  let aiProviders: AiProviderSet | undefined;
  const aiUsageTracker = new AiUsageTracker();
  if (ctx.options.ai) {
    ctx.logger.info("ai: loading provider config");
    const providerName = ctx.options.provider ?? ctx.env.AI_PROVIDER;
    const lowModel = aiLowModel(ctx.env, ctx.projectConfig.aiLowModel, ctx.options.model);
    const mediumModel = aiMediumModel(ctx.env, ctx.projectConfig.aiMediumModel, ctx.options.model);
    const highModel = aiHighModel(ctx.env, ctx.projectConfig.aiHighModel, ctx.options.model);
    const low = createAiProvider(ctx.env, ctx.options.provider, lowModel);
    const medium = createAiProvider(ctx.env, ctx.options.provider, mediumModel);
    const high = createAiProvider(ctx.env, ctx.options.provider, highModel);
    aiProviders = {
      low: withUsageTracking(low.provider, aiUsageTracker, "low", low.model),
      medium: withUsageTracking(medium.provider, aiUsageTracker, "medium", medium.model),
      high: withUsageTracking(high.provider, aiUsageTracker, "high", high.model),
      critic: ctx.projectConfig.aiCritic === false ? undefined : withUsageTracking(medium.provider, aiUsageTracker, "medium", medium.model)
    };
    aiMeta = { provider: low.provider.name, model: `low:${low.model} / medium:${medium.model} / high:${high.model}${ctx.projectConfig.aiCritic === false ? " / critic:disabled" : " / critic:medium"}` };
    ctx.logger.info(`ai: provider=${aiMeta.provider} low=${low.model} medium=${medium.model} high=${high.model}${ctx.projectConfig.aiCritic === false ? " critic=disabled" : " critic=medium"}`);
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
    const cacheRows = db.prepare("SELECT path, sha256 FROM scan_cache WHERE repo_path = ?").all(ctx.repoPath) as Array<{ path: string; sha256: string }>;
    const cacheMap = new Map(cacheRows.map((row) => [row.path, row.sha256]));
    // If --diff is set, restrict scanning to files changed in git
    let diffFiles: string[] | undefined;
    if (ctx.options.diff !== undefined) {
      diffFiles = getGitDiffFiles(ctx.repoPath, typeof ctx.options.diff === "string" ? ctx.options.diff : undefined);
      ctx.logger.info(`diff: ${diffFiles.length} files changed since ${typeof ctx.options.diff === "string" ? ctx.options.diff : "HEAD"}`);
    }
    const allFiles = indexRepository(db, scanId, ctx.repoPath, {
      maxFiles: ctx.options.maxFiles,
      maxFileSize: ctx.options.maxFileSize,
      include: [...(ctx.options.include ?? []), ...(diffFiles ?? [])],
      exclude: ctx.options.exclude,
      cacheMap: (ctx.options.incremental || diffFiles !== undefined) ? cacheMap : undefined
    });
    ctx.logger.info(`index: indexed ${allFiles.length} files (${allFiles.filter(f => !f.content).length} cached/unchanged)`);
    const aiInstructions = loadAiInstructions(ctx.repoPath);
    if (aiInstructions.path) ctx.logger.info(`ai-instructions: loaded ${aiInstructions.path} chars=${aiInstructions.chars}`);
    const changedPaths = new Set(allFiles.filter((file) => {
      if (!file.content) return false; // cached, unchanged — skip
      const cached = db.prepare("SELECT sha256 FROM scan_cache WHERE repo_path = ? AND path = ?").get(ctx.repoPath, file.path) as { sha256?: string } | undefined;
      return cached?.sha256 !== sha256(file.content);
    }).map((file) => file.path));
    const localFiles = ctx.options.incremental ? allFiles.filter((file) => changedPaths.has(file.path)) : allFiles;
    if (ctx.options.incremental) ctx.logger.info(`incremental: changed files=${changedPaths.size} localScannerFiles=${localFiles.length}`);
    for (const file of allFiles) {
      const record = (getScanBundle(db, scanId).files as any[]).find((item) => item.path === file.path);
      if (record?.sha256) upsertScanCache(db, ctx.repoPath, { path: file.path, sha256: record.sha256, language: file.language, lineCount: file.lineCount });
    }
    ctx.logger.info("scanners: running local scanners in parallel");
    const localScannerJobs = [
      Promise.resolve().then(() => { const r = runCustomRules(localFiles); ctx.logger.info(`scanners: custom rules produced ${r.length} results`); return r; }),
      Promise.resolve().then(() => { const r = runTaintLite(localFiles); ctx.logger.info(`scanners: taint-lite produced ${r.length} results`); return r; }),
      Promise.resolve().then(() => { const r = runTaintFlow(localFiles); ctx.logger.info(`scanners: taint-flow produced ${r.length} results`); return r; }),
      Promise.resolve().then(() => { const r = runConfigChecks(localFiles); ctx.logger.info(`scanners: config checks produced ${r.length} results`); return r; }),
      Promise.resolve().then(() => { const r = runQualityChecks(localFiles); ctx.logger.info(`scanners: quality checks produced ${r.length} results`); return r; })
    ];
    const [customResults, taintResults, taintFlowResults, configResults, qualityResults] = await Promise.all(localScannerJobs);
    ctx.logger.info("scanners: running external scanners");
    const scannerJobs = [
      runLoggedScanner(ctx, db, scanId, "semgrep", () => runSemgrep(ctx.repoPath, scannerTimeout(ctx, "semgrep"))),
      runLoggedScanner(ctx, db, scanId, "gitleaks", () => runGitleaks(ctx.repoPath, scannerTimeout(ctx, "gitleaks"))),
      runLoggedScanner(ctx, db, scanId, "trivy", () => runTrivy(ctx.repoPath, scannerTimeout(ctx, "trivy"))),
      runLoggedScanner(ctx, db, scanId, "osv-scanner", () => runOsv(ctx.repoPath, scannerTimeout(ctx, "osv-scanner"))),
      runLoggedScanner(ctx, db, scanId, "bearer", () => runBearer(ctx.repoPath, scannerTimeout(ctx, "bearer")))
    ];
    const scanners = await Promise.all(scannerJobs);
    const preliminaryScannerResults = [
      ...customResults,
      ...taintResults,
      ...taintFlowResults,
      ...configResults,
      ...qualityResults,
      ...scanners.flatMap((scan) => {
        if (scan.warning) warnings.push(scan.warning);
        return scan.results;
      })
    ];
    ctx.logger.info("scanners: running compliance checks");
    const complianceResults = runComplianceChecks(allFiles, preliminaryScannerResults);
    ctx.logger.info(`scanners: compliance checks produced ${complianceResults.length} results`);
    ctx.logger.info("scanners: running correlation checks");
    const correlationResults = runCorrelationChecks(allFiles, preliminaryScannerResults);
    ctx.logger.info(`scanners: correlation checks produced ${correlationResults.length} results`);
    const rawScannerResults = [...preliminaryScannerResults, ...complianceResults, ...correlationResults];
    const configuredResults = applyProjectPolicy(rawScannerResults, ctx);
    const suppressed = applySuppressions(ctx.repoPath, allFiles, configuredResults);
    if (suppressed.summary.suppressed) ctx.logger.info(`suppressions: removed ${suppressed.summary.suppressed} results`);
    const scannerResults = attachScannerFingerprints(suppressed.results);
    ctx.logger.info(`scanners: total ${scannerResults.length} results`);
    ctx.logger.info("db: storing scanner results");
    for (const result of scannerResults) insertScannerResult(db, scanId, result);
    const triageCandidates = planAiTriageCandidates(scannerResults, ctx.options.maxAiFindings);
    const targetActiveFindings = Math.min(ctx.options.aiTriageTargetCodeFindings, ctx.options.maxAiFindings);
    ctx.logger.info(`triage: planned ${triageCandidates.length} AI scanner candidates max=${ctx.options.maxAiFindings} targetActive=${targetActiveFindings}`);
    const aiBudget = { triageContextChars: 0, estimatedTriageTokens: 0, triagedScannerResults: 0, triageTargetCodeFindings: targetActiveFindings };
    const findings = aiProviders
      ? await runAiTriageBatches({
        providers: aiProviders,
        candidates: triageCandidates,
        files: allFiles,
        scannerResults,
        aiInstructions: aiInstructions.content,
        maxContextChars: ctx.env.CODEGUARDIAN_MAX_CONTEXT_CHARS,
        targetActiveFindings,
        log: (message) => ctx.logger.info(message),
        aiBudget
      })
      : scannerResults.filter((result) => result.scanner !== "compliance").map(deterministicFinding);
    aiBudget.estimatedTriageTokens = Math.ceil(aiBudget.triageContextChars / 4);
    if (aiBudget.triagedScannerResults) ctx.logger.info(`ai-budget: triaged=${aiBudget.triagedScannerResults} context chars=${aiBudget.triageContextChars} estimatedTokens=${aiBudget.estimatedTriageTokens}`);
    if (aiProviders && ctx.options.aiAudit) {
      ctx.logger.info(`ai-audit: enabled maxFiles=${ctx.options.maxAiAuditFiles} maxRounds=${ctx.options.maxAiAuditRounds} maxChars=${ctx.options.maxAiAuditChars}`);
      const auditFindings = await runExploratoryAudit(aiProviders.medium, allFiles, scannerResults, {
        maxFiles: ctx.options.maxAiAuditFiles,
        maxRounds: ctx.options.maxAiAuditRounds,
        maxChars: ctx.options.maxAiAuditChars,
        aiInstructions: aiInstructions.content
      }, (message) => ctx.logger.info(message));
      findings.push(...auditFindings);
      ctx.logger.info(`ai-audit: added ${auditFindings.length} findings`);
    } else if (aiProviders) {
      ctx.logger.info("ai-audit: disabled");
    }
    const finalFindings = applyTriageMemory(db, ctx.repoPath, scanId, attachFindingFingerprints(findings.map(classifyFindingState))).map((finding) => ({ ...finding, exploitabilityScore: localExploitabilityScore(finding) }));
    ctx.logger.info(`triage: produced ${finalFindings.length} findings`);
    ctx.logger.info("db: storing findings");
    for (const finding of finalFindings) insertFinding(db, scanId, finding);
    ctx.logger.info("db: marking scan completed");
    finishScan(db, scanId, "completed");
    const baselineDiff = buildBaselineDiff(db, ctx.repoPath, scanId, ctx.options.baseline);
    const bundle = { ...getScanBundle(db, scanId), toolStatuses, baselineDiff, suppressions: suppressed.summary, aiBudget, aiUsage: aiUsageTracker.summary(), aiInstructions: { path: aiInstructions.path, chars: aiInstructions.chars, loaded: Boolean(aiInstructions.path) }, projectConfig: ctx.projectConfig, incremental: { enabled: ctx.options.incremental, changedFiles: changedPaths.size, localScannerFiles: localFiles.length } };
    ctx.logger.info(`reports: writing format=${ctx.options.format} out=${ctx.outDir}`);
    const reportFiles = writeReports(ctx.outDir, ctx.options.format, bundle, warnings);
    for (const file of reportFiles) ctx.logger.info(`reports: wrote ${file}`);
    if (ctx.options.ci) emitCiAnnotations(finalFindings, ctx.options.failOn);
    return { scanId, reportFiles, warnings, exitCode: failExitCode(finalFindings, ctx.options.failOn) };
  } catch (error) {
    ctx.logger.error(`scan failed: ${error instanceof Error ? error.message : String(error)}`);
    finishScan(db, scanId, "failed");
    throw error;
  } finally {
    ctx.logger.info("db: closing database");
    db.close();
  }
}

function createRequestedContextResolver(files: Array<{ path: string; content: string; lineCount: number }>, maxChars: number) {
  return (requestedFiles: string[], requestedSymbols: string[]) => {
    const remaining = { chars: Math.min(maxChars, 50_000) };
    const missing: string[] = [];
    const byPath = new Map(files.map((file) => [file.path.replaceAll("\\", "/"), file]));
    const fileContexts = [...new Set(requestedFiles.map((item) => item.replaceAll("\\", "/").replace(/^\/+/, "")))].slice(0, 5).flatMap((filePath) => {
      const file = byPath.get(filePath);
      if (!file) {
        missing.push(filePath);
        return [];
      }
      return [clipFileContext(file.path, file.content, 1, Math.min(file.lineCount, 220), remaining)];
    }).filter(Boolean);
    const symbolContexts = [...new Set(requestedSymbols.map((item) => item.trim()).filter(Boolean))].slice(0, 8).flatMap((query) => {
      const matches = findSymbolContexts(files, query, remaining);
      if (!matches.length) missing.push(query);
      return matches;
    });
    return { files: fileContexts, symbols: symbolContexts, missing };
  };
}

async function runAiTriageBatches(input: {
  providers: AiProviderSet;
  candidates: ScannerResult[];
  files: IndexedFile[];
  scannerResults: ScannerResult[];
  aiInstructions: string;
  maxContextChars: number;
  targetActiveFindings: number;
  log: (message: string) => void;
  aiBudget: { triageContextChars: number; triagedScannerResults: number };
}): Promise<Finding[]> {
  const batchSize = 25;
  const findings: Finding[] = [];
  const resolveRequestedContext = createRequestedContextResolver(input.files, input.maxContextChars);
  for (let offset = 0; offset < input.candidates.length; offset += batchSize) {
    const batch = input.candidates.slice(offset, offset + batchSize);
    input.log(`triage: auditing scanner batch ${Math.floor(offset / batchSize) + 1} results=${batch.length} active=${activeFindingCount(findings)}/${input.targetActiveFindings}`);
    for (const [index, result] of batch.entries()) {
      if (input.targetActiveFindings > 0 && activeFindingCount(findings) >= input.targetActiveFindings) break;
      const absoluteIndex = offset + index;
      input.log(`context: pack ${offset + index + 1}/${input.candidates.length} ${result.scanner}/${result.ruleId} ${result.path ?? ""}:${result.startLine ?? ""}`);
      const contextPack = buildContextPack(result, input.files, input.scannerResults, input.maxContextChars, input.aiInstructions);
      input.aiBudget.triageContextChars += JSON.stringify(contextPack).length;
      input.aiBudget.triagedScannerResults += 1;
      const tier = selectAiTriageTier(result);
      const useCritic = input.providers.critic && (result.severity === "critical" || result.severity === "high");
      input.log(`triage: model tier=${tier} score=${scoreScannerResult(result)} critic=${useCritic ? "yes" : "skip"} ${result.scanner}/${result.ruleId} ${result.path ?? ""}:${result.startLine ?? ""}`);
      const provider = input.providers[tier];
      try {
        findings.push(...await aiTriage(
          provider,
          [contextPack],
          input.log,
          useCritic ? input.providers.critic : undefined,
          resolveRequestedContext,
          [formatTriageLabel(result, absoluteIndex, input.candidates.length)],
          provider
        ));
      } catch (error) {
        if (tier !== "low") {
          const fallbackTier = tier === "high" ? "medium" : "low";
          input.log(`triage: ${tier} failed, falling back to ${fallbackTier}: ${error instanceof Error ? error.message : String(error)}`);
          const fallbackProvider = input.providers[fallbackTier];
          findings.push(...await aiTriage(
            fallbackProvider,
            [contextPack],
            input.log,
            undefined,
            resolveRequestedContext,
            [formatTriageLabel(result, absoluteIndex, input.candidates.length)],
            fallbackProvider
          ));
        } else {
          throw error;
        }
      }
    }
    if (input.targetActiveFindings > 0 && activeFindingCount(findings) >= input.targetActiveFindings) {
      input.log(`triage: target active code findings reached ${activeFindingCount(findings)}/${input.targetActiveFindings}`);
      break;
    }
  }
  return findings;
}

export function selectAiTriageTier(result: ScannerResult): AiTier {
  const score = scoreScannerResult(result);
  const text = `${result.scanner} ${result.ruleId} ${result.title} ${result.category ?? ""} ${result.path ?? ""}`.toLowerCase();
  const complex = /(correlation|taint-flow|auth|authorization|tenant|ssrf|deserialization|prototype|rce|template|command|path-traversal|file-upload|cors|csrf)/.test(text);
  if (result.scanner === "correlation" || (result.severity === "critical" && complex) || (result.severity === "high" && complex && score >= 105)) return "high";
  if (result.severity === "critical" || result.severity === "high" || score >= 75) return "medium";
  return "low";
}

function formatTriageLabel(result: ScannerResult, index: number, total: number): string {
  return `${index + 1}/${total} ${result.scanner}/${result.ruleId} ${result.path ?? ""}:${result.startLine ?? ""}`;
}

function activeFindingCount(findings: Finding[]): number {
  return findings.filter((finding) => finding.status !== "false_positive" && finding.category !== "dependency").length;
}

function findSymbolContexts(files: Array<{ path: string; content: string; lineCount: number }>, query: string, remaining: { chars: number }) {
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`\\b${escaped}\\b`);
  const matches = [];
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    const index = lines.findIndex((line) => regex.test(line));
    if (index === -1) continue;
    const start = Math.max(1, index + 1 - 35);
    const end = Math.min(file.lineCount, index + 1 + 80);
    matches.push({ query, ...clipFileContext(file.path, file.content, start, end, remaining) });
    if (matches.length >= 5 || remaining.chars <= 0) break;
  }
  return matches;
}

function clipFileContext(pathName: string, content: string, startLine: number, endLine: number, remaining: { chars: number }) {
  const raw = lineSlice(content, startLine, endLine).split(/\r?\n/).map((line, offset) => `${startLine + offset}: ${line}`).join("\n");
  const clipped = redactSecrets(raw).slice(0, Math.max(0, remaining.chars));
  remaining.chars -= clipped.length;
  return { path: pathName, startLine, endLine, content: clipped };
}

function scannerTimeout(ctx: RunContext, name: string): number | undefined {
  return ctx.projectConfig.scannerTimeouts?.[name];
}

function applyProjectPolicy(results: ScannerResult[], ctx: RunContext): ScannerResult[] {
  const disabled = new Set(ctx.projectConfig.disabledRules ?? []);
  const overrides = ctx.projectConfig.severityOverrides ?? {};
  return results
    .filter((result) => !disabled.has(result.ruleId) && !disabled.has(`${result.scanner}/${result.ruleId}`))
    .filter((result) => ruleAllowedByProfile(result.ruleId, result.category, result.path, ctx.options.profile))
    .map((result) => overrides[result.ruleId] || overrides[`${result.scanner}/${result.ruleId}`] ? { ...result, severity: overrides[result.ruleId] ?? overrides[`${result.scanner}/${result.ruleId}`] } : result);
}

function localExploitabilityScore(finding: Finding): number {
  const severityBase: Record<string, number> = { critical: 85, high: 70, medium: 45, low: 20, info: 5 };
  const confidenceBonus: Record<string, number> = { confirmed: 10, high: 8, medium: 0, low: -10 };
  let score = (severityBase[finding.severity] ?? 30) + (confidenceBonus[finding.confidence] ?? 0);
  const text = `${finding.category} ${finding.path ?? ""} ${finding.source ?? ""} ${finding.sink ?? ""}`.toLowerCase();
  if (/(route|controller|api|admin|auth|bin\/|cli)/.test(text)) score += 8;
  if (/(secret|command|deserialization|ssrf)/.test(text)) score += 8;
  if (finding.status === "confirmed_true_positive") score += 8;
  if (finding.status === "likely_true_positive") score += 3;
  if (finding.status === "security_hotspot" || finding.status === "needs_context") score -= 8;
  if (finding.status === "false_positive") score = 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

function classifyFindingState(finding: Finding): Finding {
  if (finding.status === "false_positive") return finding;
  if (finding.status === "needs_dynamic_test") return { ...finding, status: "security_hotspot" };
  if (finding.status === "confirmed" && ["confirmed", "high"].includes(finding.confidence)) return { ...finding, status: "confirmed_true_positive" };
  if (finding.confidence === "high" && ["critical", "high"].includes(finding.severity)) return { ...finding, status: "likely_true_positive" };
  if (finding.confidence === "low") return { ...finding, status: "needs_context" };
  return finding;
}

function applyTriageMemory(db: ReturnType<typeof openDatabase>, repoPath: string, scanId: string, findings: Finding[]): Finding[] {
  const rows = db.prepare(`
    SELECT f.fingerprint, f.status, f.reasoning
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    WHERE s.repo_path = ? AND f.scan_id != ? AND f.fingerprint IS NOT NULL
    ORDER BY s.started_at DESC
  `).all(repoPath, scanId) as Array<{ fingerprint: string; status: Finding["status"]; reasoning?: string }>;
  const memory = new Map<string, { status: Finding["status"]; reasoning?: string }>();
  for (const row of rows) if (!memory.has(row.fingerprint)) memory.set(row.fingerprint, row);
  return findings.map((finding) => {
    const remembered = finding.fingerprint ? memory.get(finding.fingerprint) : undefined;
    if (!remembered) return finding;
    if (remembered.status === "false_positive") {
      return { ...finding, status: "false_positive", confidence: "low", reasoning: `${finding.reasoning}\nTriage memory: previous scan marked this fingerprint false_positive. ${remembered.reasoning ?? ""}` };
    }
    if (remembered.status === "confirmed_true_positive" || remembered.status === "confirmed") {
      return { ...finding, status: "confirmed_true_positive", confidence: finding.confidence === "low" ? "medium" : finding.confidence, reasoning: `${finding.reasoning}\nTriage memory: previous scan confirmed this fingerprint as true positive.` };
    }
    return finding;
  });
}

async function runLoggedScanner(ctx: RunContext, db: ReturnType<typeof openDatabase>, scanId: string, name: string, run: () => Promise<{ results: unknown[]; warning?: string; code?: number | null }>): Promise<{ results: any[]; warning?: string }> {
  const start = Date.now();
  const startedAt = new Date().toISOString();
  ctx.logger.info(`scanner:${name}: start`);
  const result = await run();
  const elapsedMs = Date.now() - start;
  const seconds = (elapsedMs / 1000).toFixed(1);
  ctx.logger.info(`scanner:${name}: done results=${result.results.length} elapsed=${seconds}s${result.warning ? " warning=yes" : ""}`);
  if (result.warning) ctx.logger.warn(`scanner:${name}: ${result.warning.split(/\r?\n/)[0]}`);
  insertScannerRun(db, {
    scanId,
    scanner: name,
    image: scannerImages()[name],
    command: name,
    startedAt,
    elapsedMs,
    exitCode: result.code ?? null,
    resultCount: result.results.length,
    warning: result.warning ?? null,
    metadataJson: JSON.stringify({ timeoutMs: ctx.projectConfig.scannerTimeouts?.[name] ?? null })
  });
  return result as { results: any[]; warning?: string };
}

export function writeReports(outDir: string, format: string, bundle: unknown, warnings: string[]): string[] {
  const reportBase = buildReportBase(bundle);
  cleanupUnrequestedReports(outDir, format);
  const files: string[] = [];
  if (format === "json" || format === "all") files.push(writeJsonReport(outDir, bundle, reportBase));
  if (format === "markdown" || format === "all") files.push(writeMarkdownReport(outDir, bundle, warnings, reportBase));
  if (format === "html" || format === "all") files.push(writeHtmlReport(outDir, bundle, warnings, reportBase));
  if (format === "sarif" || format === "all") files.push(writeSarifReport(outDir, bundle, reportBase));
  const ruleExport = writeRuleExport(outDir, bundle, reportBase);
  if (ruleExport) files.push(ruleExport);
  return files;
}

function cleanupUnrequestedReports(outDir: string, format: string): void {
  if (format === "all") return;
  const keepExt = format === "markdown" ? ".md" : format === "html" ? ".html" : format === "json" ? ".json" : format === "sarif" ? ".sarif" : "";
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

/** Output GitHub Actions annotations for findings matching the failOn threshold. */
function emitCiAnnotations(findings: Array<{ path?: string | null; startLine?: number | null; title: string; severity: string; category: string; reasoning: string; status?: string | null }>, failOn: string): void {
  const threshold = failOn === "none" ? SEVERITY_ORDER.length - 1 : SEVERITY_ORDER.indexOf(failOn as any);
  for (const finding of findings) {
    if (finding.status === "false_positive") continue;
    const findingLevel = SEVERITY_ORDER.indexOf(finding.severity as any);
    if (findingLevel > threshold) continue;
    const file = finding.path ?? "";
    const line = finding.startLine ?? 1;
    const title = `[${finding.severity}] ${finding.category}: ${finding.title}`;
    const message = finding.reasoning.slice(0, 500).replace(/\n/g, "%0A");
    // GitHub Actions annotation format
    console.log(`::error file=${file},line=${line},title=${title}::${message}`);
  }
  const summaryLine = findings.filter((f) => !f.status || f.status !== "false_positive").length;
  console.log(`::notice::CodeGuardian scan complete: ${summaryLine} findings (fail-on: ${failOn})`);
}

/** Get files changed in git vs HEAD or a specific ref. Returns relative paths. */
export function getGitDiffFiles(repoPath: string, ref?: string): string[] {
  try {
    const target = typeof ref === "string" && ref ? ref : "HEAD";
    const output = execSync(`git -C "${repoPath}" diff --name-only ${target}`, { encoding: "utf8", timeout: 30_000 });
    return output.split(/\r?\n/).filter(Boolean);
  } catch {
    return [];
  }
}
