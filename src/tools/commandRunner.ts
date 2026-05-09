import { spawn } from "node:child_process";
import { assertAllowedExecutable } from "./policy.js";

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export function runCommand(executable: string, args: string[], cwd: string, timeoutMs = 120_000): Promise<CommandResult> {
  assertAllowedExecutable(executable);
  return new Promise((resolve) => {
    const child = spawn(executable, args, { cwd, shell: false });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (data) => { stdout += data.toString(); });
    child.stderr.on("data", (data) => { stderr += data.toString(); });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: stderr + error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

export async function checkTool(name: string): Promise<{ available: boolean; version?: string; error?: string }> {
  const result = await runCommand(name, ["--version"], process.cwd(), 15_000).catch((error: Error) => ({ code: 127, stdout: "", stderr: error.message }));
  if (result.code === 0 || result.stdout || result.stderr) {
    return { available: result.code !== 127, version: (result.stdout || result.stderr).split(/\r?\n/)[0] };
  }
  return { available: false, error: "not found" };
}
