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

function addCommonOptions(command: Command): Command {
  return command
    .option("--out <dir>", "output directory")
    .option("--format <format>", "markdown|json|sarif|all", "all")
    .option("--ai", "enable AI triage")
    .option("--no-ai", "disable AI triage")
    .option("--provider <provider>", "openai|anthropic|deepseek|openrouter")
    .option("--model <model>", "AI model")
    .option("--target <url>", "dynamic target")
    .option("--allow-host <host>", "allow host", collect, [])
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
    .option("--fail-on <severity>", "critical|high|medium|low|none", "none")
    .option("--verbose", "verbose logging");
}

function collect(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.name("codeguardian").description("AI-assisted local security scanner").version("0.1.0");

  addCommonOptions(program.command("scan <repoPath>").description("Index, scan, triage, and report")).action(async (repoPath, options) => {
    const ctx = createRunContext(repoPath, options);
    const result = await runScan(ctx);
    console.log(`scan ${result.scanId} complete`);
    for (const file of result.reportFiles) console.log(file);
    process.exitCode = result.exitCode;
  });

  addCommonOptions(program.command("index <repoPath>").description("Index only")).action(async (repoPath, options) => {
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

  program.command("test-web").requiredOption("--target <url>").option("--allow-host <host>", "allow host", collect, []).option("--out <dir>", "output directory", "codeguardian-report").option("--run-approved", "run approved actions").action(async (options) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    const allowedHosts = [...envAllowHosts(env), ...(options.allowHost ?? [])];
    const curl = await runCurlTool(db, { target: options.target, allowedHosts, runApproved: Boolean(options.runApproved) });
    const browser = await runPuppeteerTool(db, { target: options.target, allowedHosts, outDir: path.resolve(options.out), runApproved: Boolean(options.runApproved) });
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

  program.command("report <scanId>").option("--out <dir>", "output directory", "codeguardian-report").option("--format <format>", "markdown|json|sarif|all", "all").action((scanId, options) => {
    const env = loadEnv();
    const db = openDatabase(path.resolve(env.CODEGUARDIAN_DB_PATH));
    const bundle = getScanBundle(db, scanId);
    for (const file of writeReports(path.resolve(options.out), options.format, bundle, [])) console.log(file);
    db.close();
  });

  await program.parseAsync(argv);
}
