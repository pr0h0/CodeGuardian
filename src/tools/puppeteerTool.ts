import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer";
import type { Db } from "../db/database.js";
import { createApproval, findApproved } from "./approvals.js";
import { isAllowedHost } from "./policy.js";
import { ensureDir } from "../utils/paths.js";

export async function runPuppeteerTool(db: Db, input: { scanId?: string; target: string; allowedHosts: string[]; outDir: string; runApproved?: boolean }) {
  if (!isAllowedHost(input.target, input.allowedHosts) && !(input.runApproved && findApproved(db, "puppeteer", input.target))) {
    const id = createApproval(db, { scanId: input.scanId, actionType: "puppeteer", commandPreview: `open ${input.target}`, risk: "medium", reason: "Browser test target is not allowlisted", target: input.target });
    return { approved: false, approvalId: id };
  }
  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  const page = await browser.newPage();
  const consoleErrors: string[] = [];
  const networkFailures: string[] = [];
  page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text()); });
  page.on("requestfailed", (req) => networkFailures.push(`${req.url()} ${req.failure()?.errorText ?? ""}`));
  await page.goto(input.target, { waitUntil: "networkidle2", timeout: 30_000 });
  await new Promise((resolve) => setTimeout(resolve, 500));
  const screenshotDir = ensureDir(path.join(input.outDir, "screenshots"));
  const screenshot = path.join(screenshotDir, "browser-check.png");
  await page.screenshot({ path: screenshot, fullPage: true });
  const text = await page.evaluate(() => document.body.innerText.slice(0, 5000));
  await browser.close();
  fs.writeFileSync(path.join(screenshotDir, "browser-check.json"), JSON.stringify({ target: input.target, consoleErrors, networkFailures, bodyTextSample: text }, null, 2));
  return { approved: true, screenshot, consoleErrors, networkFailures };
}
