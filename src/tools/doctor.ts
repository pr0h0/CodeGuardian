import path from "node:path";
import { checkTool, runCommand } from "./commandRunner.js";
import { scannerImages } from "../scanners/dockerFallback.js";

export async function runDoctor(repoPath: string, options: { pull?: boolean } = {}): Promise<{ ok: boolean; lines: string[] }> {
  const lines: string[] = [];
  let ok = true;
  for (const tool of ["docker", "rg", "node", "npm"]) {
    const status = await checkTool(tool);
    ok = ok && status.available;
    lines.push(`${tool}: ${status.available ? "available" : "missing"}${status.version ? ` - ${status.version}` : ""}${status.error ? ` - ${status.error}` : ""}`);
  }

  const docker = await runCommand("docker", ["info", "--format", "{{.ServerVersion}}"], path.resolve(repoPath), 20_000);
  const dockerOk = docker.code === 0;
  ok = ok && dockerOk;
  lines.push(`docker-daemon: ${dockerOk ? `available - ${docker.stdout.trim()}` : `unavailable - ${(docker.stderr || docker.stdout).split(/\r?\n/)[0] ?? ""}`}`);

  for (const [name, image] of Object.entries(scannerImages())) {
    if (options.pull && dockerOk) {
      const pull = await runCommand("docker", ["pull", image], path.resolve(repoPath), 180_000);
      ok = ok && pull.code === 0;
      lines.push(`image:${name}: ${pull.code === 0 ? "pulled" : `pull failed - ${(pull.stderr || pull.stdout).split(/\r?\n/)[0] ?? ""}`} (${image})`);
    } else {
      lines.push(`image:${name}: ${image}`);
    }
    if (dockerOk) {
      const health = await runCommand("docker", ["run", "--rm", image, ...healthArgs(name)], path.resolve(repoPath), 60_000);
      const healthy = health.code === 0 || (name === "gitleaks" && health.code === 2);
      ok = ok && healthy;
      lines.push(`health:${name}: ${healthy ? "ok" : `failed - ${(health.stderr || health.stdout).split(/\r?\n/)[0] ?? ""}`}`);
    }
  }

  return { ok, lines };
}

function healthArgs(name: string): string[] {
  if (name === "semgrep") return ["semgrep", "--version"];
  if (name === "gitleaks") return ["version"];
  if (name === "trivy") return ["--version"];
  if (name === "osv-scanner") return ["--version"];
  if (name === "bearer") return ["version"];
  return ["--version"];
}
