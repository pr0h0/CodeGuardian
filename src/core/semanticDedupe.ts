import type { ScannerResult } from "../scanners/types.js";

export interface SemanticInput {
  scanner?: string;
  ruleId?: string;
  title?: string;
  category?: string;
  severity?: string;
  path?: string;
  startLine?: number;
  endLine?: number;
  message?: string;
  source?: string;
  sink?: string;
  reasoning?: string;
  remediation?: string;
  raw?: unknown;
}

export interface DeduplicationSummary {
  deduplicatedBy: "semantic-noise-reduction";
  family: string;
  deduplicatedCount: number;
  kept: Record<string, unknown>;
  deduplicatedFrom: Array<Record<string, unknown>>;
}

export function semanticGroupKey(item: SemanticInput): string | undefined {
  if (isDependencyLike(item)) return undefined;
  if (!item.path) return undefined;
  const family = semanticFamily(item);
  if (!family) return undefined;
  return [
    normalizePath(item.path),
    family,
    lineBucket(item.startLine, lineWindow(family))
  ].join("|");
}

export function semanticFamily(item: SemanticInput): string | undefined {
  const text = searchableText(item);
  const directText = [
    item.scanner,
    item.ruleId,
    item.title,
    item.category,
    item.message,
    item.source,
    item.sink
  ].map((value) => normalizeToken(value)).join(" ");

  if (/(secret|credential|password|api[_ -]?key|token)/.test(text)
    && /(hard.?coded|hardcoded|generic.secret|detected.generic.secret|secret.assignment|express.session.hardcoded.secret|session.secret)/.test(text)) {
    return "hardcoded-secret";
  }

  if (/(command.injection|code.injection|rce|eval|safeeval|notevil|vm.runincontext|child.process|exec\(|spawn\(|shell)/.test(directText)) return "command-injection";
  if (/(session|cookie|connect\.sid|express.cookie|express.session|cookie.settings|cookie.configuration|default.cookie)/.test(directText)
    && /(secure|httponly|http.only|same.?site|domain|expires|maxage|max.age|default|name|fingerprint|session.cookie)/.test(directText)) {
    return "session-cookie-hardening";
  }
  if (/(xss|cross.site.scripting|raw.html|script.tag)/.test(directText)) return "template-xss";
  if (/(sql.injection|raw.sql|sequelize.query|\bsql\b)/.test(text)) return "sql-injection";
  if (/(ssrf|server.side.request.forgery|outbound.http|fetch\()/.test(text)) return "ssrf";
  if (/(open.redirect|redirect)/.test(text)) return "open-redirect";
  if (/(xxe|xml.external|noent|parsexml|doctype|entity.expansion)/.test(text)) return "xxe";
  if (/(nosql|\$where|mongo|mongodb)/.test(text)) return "nosql-injection";
  if (/(path.traversal|directory.traversal|non.literal.fs|filesystem|file.path|fs\.)/.test(text)) return "path-traversal";
  if (/(prototype.pollution|__proto__|constructor.prototype)/.test(text)) return "prototype-pollution";
  if (/(xss|cross.site.scripting|template|ejs|eta|raw.html|unescape|script.tag)/.test(text)) return "template-xss";
  if (/(command.injection|code.injection|rce|eval\(|safeeval|notevil|vm.runincontext|child_process|exec\(|spawn\(|shell)/.test(text)) return "command-injection";
  if (/(file.upload|zip.slip|archive|upload|originalname|mimetype|entry.path)/.test(text)) return "file-upload";
  if (/(business.logic|basket|cart|order|checkout|payment|coupon|discount|review|feedback|deluxe|quantity|price)/.test(directText)
    || /(product.review|user.review|reviewid|review.id|feedback.form|coupon.code|order.id|basket.id|cart.id)/.test(text)) return "business-logic";
  if (/(csrf|cross.site.request.forgery)/.test(text)) return "csrf-protection";

  if (/(helmet|x-powered-by|powered.by|fingerprint|security.header|http.header|reduce.server.fingerprint)/.test(directText)) {
    return "express-header-hardening";
  }

  if (/(http\.createserver|https?|tls|ssl|secure.http|transport.security|insecure.transport)/.test(directText)
    && /(http.server|without.tls|missing.secure|https.protocol.missing|using.http.server|transport.security)/.test(directText)) {
    return "transport-security";
  }

  return undefined;
}

export function exactFindingKey(item: SemanticInput): string {
  return [
    normalizePath(item.path),
    normalizeToken(item.category ?? "security"),
    normalizeTitle(item.title),
    item.startLine ?? ""
  ].join("|");
}

export function appendDeduplicationNote(text: string, count: number, summaries: Array<Record<string, unknown>>): string {
  if (count <= 0) return text;
  const labels = summaries
    .slice(0, 6)
    .map(summaryLabel)
    .filter(Boolean);
  const suffix = summaries.length > labels.length ? ", ..." : "";
  const note = `Deduplicated ${count} related ${count === 1 ? "finding" : "findings"}: ${labels.join("; ")}${suffix}`;
  return `${text.trim()}\n\n${note}`.trim();
}

export function mergeRaw(raw: unknown, summary: DeduplicationSummary): unknown {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>), semanticDeduplication: summary };
  }
  if (raw === undefined || raw === null) return { semanticDeduplication: summary };
  return { originalRaw: raw, semanticDeduplication: summary };
}

export function scannerSummary(result: ScannerResult): Record<string, unknown> {
  return {
    scanner: result.scanner,
    ruleId: result.ruleId,
    title: result.title,
    category: result.category,
    severity: result.severity,
    path: result.path,
    startLine: result.startLine,
    message: result.message?.slice(0, 300)
  };
}

function summaryLabel(item: Record<string, unknown>): string {
  const base = [item.scanner, item.ruleId, item.title].filter(Boolean).join("/");
  const message = String(item.message ?? "");
  const secretClassification = message.match(/secret classification:\s*[^)]+/i)?.[0];
  return secretClassification ? `${base} (${secretClassification})` : base;
}

export function normalizePath(value?: string): string {
  return String(value ?? "unknown").replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
}

export function normalizeTitle(value?: string): string {
  return normalizeToken(value)
    .replace(/\b(candidate|detected|finding|usage of|default|configuration|settings)\b/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function searchableText(item: SemanticInput): string {
  return [
    item.scanner,
    item.ruleId,
    item.title,
    item.category,
    item.message,
    item.source,
    item.sink,
    item.reasoning,
    item.remediation
  ].map((value) => normalizeToken(value)).join(" ");
}

export function actionabilityBonus(item: SemanticInput): number {
  const family = semanticFamily(item);
  const text = searchableText(item);
  let score = 0;

  if (family === "session-cookie-hardening") {
    if (/(no.secure|missing.secure|secure.flag|secure.not.set|`secure` not set)/.test(text)) score += 80;
    if (/(httponly|http.only|same.site|samesite)/.test(text)) score += 50;
    if (/(default.cookie.configuration|default.session.cookie.configuration)/.test(text)) score += 25;
    if (/(default.session.cookie.name|default.cookie.name|connect.sid|fingerprint)/.test(text)) score += 10;
    if (/(no.domain|domain.not.set|expires.not.set|no.expires)/.test(text)) score += 5;
    if (item.category === "xss") score -= 15;
  }

  if (family === "hardcoded-secret") {
    if (/(express.session|session.secret|express_hardcoded_secret|express-session-hardcoded-secret)/.test(text)) score += 50;
    if (/(generic.secret|generic-secret-assignment)/.test(text)) score -= 10;
  }

  return score;
}

export function isDependencyLike(item: SemanticInput): boolean {
  if (item.category === "dependency") return true;
  const scanner = item.scanner ?? "";
  const ruleId = item.ruleId ?? "";
  const raw = item.raw && typeof item.raw === "object" ? item.raw as Record<string, unknown> : {};
  return (scanner === "trivy" || scanner === "osv-scanner")
    && Boolean(raw.VulnerabilityID || raw.id || /^CVE-\d{4}-\d+$/i.test(ruleId) || /^GHSA-/i.test(ruleId));
}

function normalizeToken(value?: unknown): string {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[_-]+/g, ".")
    .replace(/[^a-z0-9.`()]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function lineBucket(value: number | undefined, window: number): string {
  if (!value) return "unknown";
  return String(Math.floor((Math.max(1, value) - 1) / window));
}

function lineWindow(family: string): number {
  if (family === "session-cookie-hardening" || family === "express-header-hardening") return 10;
  if (["sql-injection", "ssrf", "command-injection", "path-traversal", "template-xss", "file-upload"].includes(family)) return 15;
  return 5;
}
