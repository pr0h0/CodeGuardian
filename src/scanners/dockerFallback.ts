import path from "node:path";
import { runCommand } from "../tools/commandRunner.js";

export interface DockerScannerResult {
  stdout: string;
  stderr: string;
  code: number | null;
  warning?: string;
}

export interface DockerRunOptions {
  networkNone?: boolean;
  readOnly?: boolean;
}

export async function runDockerScanner(repoPath: string, image: string, args: string[], timeoutMs = 240_000, options: DockerRunOptions = {}): Promise<DockerScannerResult> {
  const absoluteRepo = path.resolve(repoPath);
  const dockerArgs = [
    "run", "--rm",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev",
    ...(options.networkNone ? ["--network", "none"] : []),
    ...(options.readOnly ? ["--read-only"] : []),
    "-v", `${absoluteRepo}:/src:ro`,
    image,
    ...args
  ];
  const result = await runCommand("docker", dockerArgs, process.cwd(), timeoutMs);
  if (result.code === 127) return { ...result, warning: "docker not available for scanner fallback" };
  if (/permission denied|Cannot connect to the Docker daemon/i.test(result.stderr)) {
    return { ...result, warning: `docker scanner fallback unavailable: ${result.stderr.split(/\r?\n/)[0]}` };
  }
  return result;
}

export function scannerImages(): Record<string, string> {
  return {
    semgrep: process.env.CODEGUARDIAN_IMAGE_SEMGREP || "semgrep/semgrep:1.99.0",
    gitleaks: process.env.CODEGUARDIAN_IMAGE_GITLEAKS || "zricethezav/gitleaks:v8.21.2",
    trivy: process.env.CODEGUARDIAN_IMAGE_TRIVY || "aquasec/trivy:0.56.2",
    "osv-scanner": process.env.CODEGUARDIAN_IMAGE_OSV || "ghcr.io/google/osv-scanner:v1.9.1",
    bearer: process.env.CODEGUARDIAN_IMAGE_BEARER || "bearer/bearer:1.49.0"
  };
}
