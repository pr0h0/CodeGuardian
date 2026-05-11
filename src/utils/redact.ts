const patterns: RegExp[] = [
  /Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /Cookie:\s*[^\\n]+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\b(?:sk|pk|ghp|glpat|xox[baprs])-?[A-Za-z0-9_]{16,}\b/g,
  /((?:api[_-]?key|token|password|secret|passwd|pwd)\s*[:=]\s*['"]?)[^'"\s]+/gi
];

let redactionEnabled = true;

export function setRedactionEnabled(enabled: boolean): void {
  redactionEnabled = enabled;
}

export function isRedactionEnabled(): boolean {
  return redactionEnabled;
}

export function redactSecrets(input: string): string {
  if (!redactionEnabled) return input;
  let output = input;
  for (const pattern of patterns) {
    output = output.replace(pattern, (match, prefix) => `${typeof prefix === "string" ? prefix : ""}[REDACTED]`);
  }
  return output;
}
