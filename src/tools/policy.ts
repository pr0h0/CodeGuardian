export const ALLOWED_EXECUTABLES = new Set(["semgrep", "gitleaks", "trivy", "osv-scanner", "rg", "node", "npm", "curl", "docker"]);
export const DISALLOWED_EXECUTABLES = new Set(["bash", "sh", "rm", "sudo", "ssh", "scp", "nc", "nmap"]);

export function assertAllowedExecutable(executable: string): void {
  if (DISALLOWED_EXECUTABLES.has(executable) || !ALLOWED_EXECUTABLES.has(executable)) {
    throw new Error(`Executable not allowed by policy: ${executable}`);
  }
}

export function isAllowedHost(urlText: string, allowedHosts: string[]): boolean {
  const url = new URL(urlText);
  return ["http:", "https:"].includes(url.protocol) && allowedHosts.includes(url.hostname);
}

export function requestNeedsApproval(method: string, target: string, allowedHosts: string[], body = ""): boolean {
  const safeMethod = ["GET", "HEAD"].includes(method.toUpperCase());
  if (!isAllowedHost(target, allowedHosts)) return true;
  if (!safeMethod) return true;
  return /(delete|drop|truncate|shutdown|format|overwrite)/i.test(body);
}
