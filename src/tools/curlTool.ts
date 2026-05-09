import { runCommand } from "./commandRunner.js";
import { requestNeedsApproval } from "./policy.js";
import { createApproval, findApproved } from "./approvals.js";
import type { Db } from "../db/database.js";
import { redactSecrets } from "../utils/redact.js";

export async function runCurlTool(db: Db, input: { scanId?: string; target: string; method?: string; allowedHosts: string[]; body?: string; runApproved?: boolean }) {
  const method = (input.method ?? "GET").toUpperCase();
  if (requestNeedsApproval(method, input.target, input.allowedHosts, input.body ?? "") && !(input.runApproved && findApproved(db, "curl", input.target))) {
    const id = createApproval(db, { scanId: input.scanId, actionType: "curl", commandPreview: `${method} ${input.target}`, risk: method === "GET" ? "medium" : "high", reason: "Dynamic HTTP request requires approval", target: input.target });
    return { approved: false, approvalId: id };
  }
  const args = ["-i", "-sS", "-X", method, input.target];
  if (input.body) args.push("--data", input.body);
  const result = await runCommand("curl", args, process.cwd(), 60_000);
  return { approved: true, response: { code: result.code, stdout: redactSecrets(result.stdout), stderr: redactSecrets(result.stderr) } };
}
