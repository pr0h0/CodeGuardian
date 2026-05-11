export interface SecretClassification {
  kind: "real-looking" | "placeholder" | "local-dev" | "test-fixture" | "unknown";
  confidence: "high" | "medium" | "low";
}

export function classifySecret(text: string, filePath = ""): SecretClassification {
  const value = String(text);
  const lower = `${filePath} ${value}`.toLowerCase();
  if (/(fixture|fixtures|spec|test|tests|mock|example|sample)/.test(lower)) return { kind: "test-fixture", confidence: "medium" };
  if (/(localhost|127\.0\.0\.1|local[-_]?dev|dummy|changeme|example|password|admin|test|fake|placeholder)/.test(lower)) return { kind: "placeholder", confidence: "medium" };
  if (/localhost-key|self[-_]?signed|\.pem/.test(lower)) return { kind: "local-dev", confidence: "medium" };
  if (/(sk-|ghp_|glpat-|xox[baprs]-|-----BEGIN|AKIA|AIza|eyJ[A-Za-z0-9_-]+\.)/.test(value)) return { kind: "real-looking", confidence: "high" };
  if (/[A-Za-z0-9+/=_-]{24,}/.test(value) && /(?:secret|token|key|password|passwd|pwd)/i.test(value)) return { kind: "real-looking", confidence: "medium" };
  return { kind: "unknown", confidence: "low" };
}
