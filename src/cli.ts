import { Command } from "commander";
import path from "node:path";
import { createRunContext } from "./core/runContext.js";
import { runScan, writeReports } from "./core/scanner.js";
import { openDatabase } from "./db/database.js";
import { createScan, finishScan, getScanBundle } from "./db/repositories.js";
import { indexRepository } from "./repo/repoIndexer.js";
import { checkTool } from "./tools/commandRunner.js";
import { envAllowHosts, loadEnv } from "./config/env.js";
import { resolveApproval } from "./tools/approvals.js";
import { runCurlTool } from "./tools/curlTool.js";
import { runPuppeteerTool } from "./tools/puppeteerTool.js";
import { runDoctor } from "./tools/doctor.js";

function addScanOptions(command: Command): Command {
  return command
    .option("--out <dir>", "output directory")
    .option("--format <format>", "markdown|html|json|sarif|all", "all")
    .option("--ai", "enable AI triage")
    .option("--no-ai", "disable AI triage")
    .option("--provider <provider>", "openai|anthropic|deepseek|openrouter")
    .option("--model <model>", "AI model")
    .option("--max-files <number>", "max files", parseInt)
    .option("--max-file-size <bytes>", "max file size", parseInt)
    .option("--max-ai-findings <number>", "max high-signal scanner results to send to AI", parseInt)
    .option("--ai-audit", "enable AI exploratory source audit")
    .option("--no-ai-audit", "disable AI exploratory source audit")
    .option("--max-ai-audit-files <number>", "max source files AI exploratory audit may inspect", parseInt)
    .option("--max-ai-audit-rounds <number>", "max AI exploratory audit request rounds", parseInt)
    .option("--max-ai-audit-chars <number>", "max total source chars sent during AI exploratory audit", parseInt)
    .option("--include <glob>", "include glob", collect, [])
    .option("--exclude <glob>", "exclude glob", collect, [])
    .option("--baseline <scanId>", "baseline scan id, latest, or none", "latest")
    .option("--profile <profile>", "all|web|cli|php|ruby|rails|laravel|node|python")
    .option("--incremental", "only run local deterministic scanners on changed files; external Docker scanners still scan full repo")
    .option("--fail-on <severity>", "critical|high|medium|low|none", "none")
    .option("--verbose", "verbose logging");
}

function addIndexOptions(command: Command): Command {
  return command
    .option("--max-files <number>", "max files", parseInt)
    .option("--max-file-size <bytes>", "max file size", parseInt)
    .option("--include <glob>", "include glob", collect, [])
    .option("--exclude <glob>", "exclude glob", collect, [])
    .option("--verbose", "verbose logging");
}

function collect(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.name("codeguardian").description("AI-assisted local security scanner").version("0.1.0");

  addScanOptions(program.command("scan <repoPath>").description("Index, scan, triage, and report")).action(async (repoPath, options) => {
    const ctx = createRunContext(repoPath, options);
    const result = await runScan(ctx);
    console.log(`scan ${result.scanId} complete`);
    for (const file of result.reportFiles) console.log(file);
    process.exitCode = result.exitCode;
  });

  addIndexOptions(program.command("index <repoPath>").description("Index only")).action(async (repoPath, options) => {
    const ctx = createRunContext(repoPath, options);
    const db = openDatabase(path.resolve(ctx.repoPath, ctx.env.CODEGUARDIAN_DB_PATH));
    const scanId = createScan(db, ctx.repoPath, ctx.options);
    const files = indexRepository(db, scanId, ctx.repoPath, { maxFiles: ctx.options.maxFiles, maxFileSize: ctx.options.maxFileSize, include: ctx.options.include, exclude: ctx.options.exclude });
    finishScan(db, scanId, "indexed");
    db.close();
    console.log(`indexed ${files.length} files in scan ${scanId}`);
  });

  program.command("tools <repoPath>").description("Check tool availability").action(async () => {
    const tools = ["docker", "rg", "node", "npm"];
    for (const tool of tools) {
      const status = await checkTool(tool);
      console.log(`${tool}: ${status.available ? "available" : "missing"}${status.version ? ` - ${status.version}` : ""}${status.error ? ` - ${status.error}` : ""}`);
    }
    try {
      const puppeteer = await import("puppeteer");
      console.log(`puppeteer/chrome: available - ${Boolean(puppeteer.default)}`);
    } catch (error) {
      console.log(`puppeteer/chrome: missing - ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  program.command("doctor <repoPath>").description("Check local scanner environment").option("--pull", "pull pinned scanner images").action(async (repoPath, options) => {
    const result = await runDoctor(repoPath, { pull: Boolean(options.pull) });
    for (const line of result.lines) console.log(line);
    process.exitCode = result.ok ? 0 : 1;
  });

  program.command("test-web").option("--target <url>", "target URL; defaults to CODEGUARDIAN_DEFAULT_TARGET").option("--allow-host <host>", "allow host", collect, []).option("--out <dir>", "output directory").option("--run-approved", "run approved actions").action(async (options) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    const target = options.target ?? env.CODEGUARDIAN_DEFAULT_TARGET;
    const outDir = path.resolve(options.out ?? env.CODEGUARDIAN_REPORT_DIR);
    const allowedHosts = [...envAllowHosts(env), ...(options.allowHost ?? [])];
    const requireApproval = env.CODEGUARDIAN_REQUIRE_APPROVAL.toLowerCase() !== "false";
    const curl = await runCurlTool(db, { target, allowedHosts, runApproved: Boolean(options.runApproved), requireApproval });
    const browser = await runPuppeteerTool(db, { target, allowedHosts, outDir, runApproved: Boolean(options.runApproved), requireApproval });
    console.log(JSON.stringify({ curl, browser }, null, 2));
    db.close();
  });

  program.command("approve <approvalId>").action((approvalId) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    console.log(resolveApproval(db, approvalId, "approved") ? "approved" : "not found or already resolved");
    db.close();
  });

  program.command("reject <approvalId>").action((approvalId) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    console.log(resolveApproval(db, approvalId, "rejected") ? "rejected" : "not found or already resolved");
    db.close();
  });

  program.command("report <scanId>").option("--out <dir>", "output directory; defaults to CODEGUARDIAN_REPORT_DIR").option("--format <format>", "markdown|json|sarif|all", "all").action((scanId, options) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    const bundle = getScanBundle(db, scanId);
    if (!bundle.scan) {
      db.close();
      throw new Error(`Scan not found: ${scanId}. Check CODEGUARDIAN_DB_PATH or use a scan id from that database.`);
    }
    for (const file of writeReports(path.resolve(options.out ?? env.CODEGUARDIAN_REPORT_DIR), options.format, bundle, [])) console.log(file);
    db.close();
  });

  await program.parseAsync(argv);
}
