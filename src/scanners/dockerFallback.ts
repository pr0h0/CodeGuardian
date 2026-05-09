import path from "node:path";
import { runCommand } from "../tools/commandRunner.js";

export interface DockerScannerResult {
  stdout: string;
  stderr: string;
  code: number | null;
  warning?: string;
}

export async function runDockerScanner(repoPath: string, image: string, args: string[], timeoutMs = 240_000): Promise<DockerScannerResult> {
  const absoluteRepo = path.resolve(repoPath);
  const result = await runCommand("docker", ["run", "--rm", "-v", `${absoluteRepo}:/src:ro`, image, ...args], process.cwd(), timeoutMs);
  if (result.code === 127) return { ...result, warning: "docker not available for scanner fallback" };
  if (/permission denied|Cannot connect to the Docker daemon/i.test(result.stderr)) {
    return { ...result, warning: `docker scanner fallback unavailable: ${result.stderr.split(/\r?\n/)[0]}` };
  }
  return result;
}
