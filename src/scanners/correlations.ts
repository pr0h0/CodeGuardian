import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";
import { analyzeDependencyReachability, packageNameFromResult } from "../repo/dependencyReachability.js";

interface Evidence {
  path?: string;
  line?: number;
  note: string;
}

interface AttackChain {
  kind: string;
  impact: string;
  confidence: "high" | "medium" | "low";
  steps: string[];
  validation: string[];
}

interface FrameworkPack {
  name: string;
  extensions: string[];
  hostPatterns: RegExp[];
  proxyIpPatterns: RegExp[];
  adminContext: RegExp;
  strongAuth: RegExp;
}

const frameworkPacks: FrameworkPack[] = [
  {
    name: "express/next/node",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
    hostPatterns: [/req\.(host|hostname)\b/i, /req\.headers\[['"]host['"]\]/i, /req\.get\(['"]host['"]\)/i, /x-forwarded-host/i],
    proxyIpPatterns: [/x-forwarded-for/i, /x-real-ip/i, /\breq\.ip\b/i, /\breq\.ips\b/i, /cf-connecting-ip/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|NODE_ENV|production|subdomain|tenant|authorize|permission|allow|next\(\)|return\s+true)\b/i,
    strongAuth: /\b(requireAuth|isAuthenticated|passport\.authenticate|authorize|requireRole|requireAdmin|rbac|session\.user|jwt\.verify)\b/i
  },
  {
    name: "flask/django/python",
    extensions: [".py"],
    hostPatterns: [/request\.host\b/i, /request\.headers\.get\(['"]host['"]\)/i, /request\.headers\[['"]host['"]\]/i, /request\.META\[['"]HTTP_HOST['"]\]/i, /request\.get_host\(\)/i, /HTTP_X_FORWARDED_HOST|x-forwarded-host/i],
    proxyIpPatterns: [/HTTP_X_FORWARDED_FOR|x-forwarded-for/i, /HTTP_X_REAL_IP|x-real-ip/i, /request\.remote_addr\b/i, /request\.META\[['"]REMOTE_ADDR['"]\]/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|is_staff|is_superuser|settings\.DEBUG|production|authorize|permission|allow|return\s+True)\b/i,
    strongAuth: /\b(login_required|permission_required|user_passes_test|IsAdminUser|is_authenticated|has_perm|staff_member_required)\b/i
  },
  {
    name: "laravel/php",
    extensions: [".php"],
    hostPatterns: [/\$_SERVER\[['"]HTTP_HOST['"]\]/i, /\$_SERVER\[['"]HTTP_X_FORWARDED_HOST['"]\]/i, /\$request->getHost\(\)/i, /Request::getHost\(\)/i, /headers->get\(['"]host['"]\)/i],
    proxyIpPatterns: [/\$_SERVER\[['"]HTTP_X_FORWARDED_FOR['"]\]/i, /\$_SERVER\[['"]REMOTE_ADDR['"]\]/i, /\$request->ip\(\)/i, /headers->get\(['"]x-forwarded-for['"]\)/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|APP_ENV|production|authorize|permission|Gate::|can\(|middleware\(['"]admin|return\s+true)\b/i,
    strongAuth: /\b(auth\(\)->check|Auth::check|middleware\(['"]auth|Gate::allows|can\(|authorize\(|policy\()/i
  },
  {
    name: "rails/ruby",
    extensions: [".rb"],
    hostPatterns: [/request\.host\b/i, /request\.host_with_port\b/i, /request\.headers\[['"]Host['"]\]/i, /request\.headers\[['"]X-Forwarded-Host['"]\]/i, /request\.subdomain\b/i],
    proxyIpPatterns: [/request\.remote_ip\b/i, /request\.ip\b/i, /request\.headers\[['"]X-Forwarded-For['"]\]/i, /HTTP_X_FORWARDED_FOR/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|Rails\.env\.production\?|production|authorize|permission|before_action|return\s+true)\b/i,
    strongAuth: /\b(before_action\s+:authenticate|authenticate_user!|authorize|policy\(|current_user|admin\?|can\?)\b/i
  },
  {
    name: "spring/java",
    extensions: [".java"],
    hostPatterns: [/getHeader\(['"]Host['"]\)/i, /getHeader\(['"]X-Forwarded-Host['"]\)/i, /getServerName\(\)/i],
    proxyIpPatterns: [/getHeader\(['"]X-Forwarded-For['"]\)/i, /getHeader\(['"]X-Real-IP['"]\)/i, /getRemoteAddr\(\)/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|production|authorize|permission|return\s+true|hasRole)\b/i,
    strongAuth: /\b(@PreAuthorize|hasRole|hasAuthority|isAuthenticated|SecurityContext|@Secured)\b/i
  },
  {
    name: "aspnet/csharp",
    extensions: [".cs"],
    hostPatterns: [/Request\.Host\b/i, /Request\.Headers\[['"]Host['"]\]/i, /Request\.Headers\[['"]X-Forwarded-Host['"]\]/i],
    proxyIpPatterns: [/Request\.Headers\[['"]X-Forwarded-For['"]\]/i, /Request\.Headers\[['"]X-Real-IP['"]\]/i, /RemoteIpAddress/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|Production|Authorize|Permission|return\s+true)\b/i,
    strongAuth: /\b(\[Authorize|User\.Identity\.IsAuthenticated|IsInRole|RequireAuthorization)\b/i
  },
  {
    name: "go/http",
    extensions: [".go"],
    hostPatterns: [/\br\.Host\b/i, /\.Header\.Get\(['"]Host['"]\)/i, /\.Header\.Get\(['"]X-Forwarded-Host['"]\)/i],
    proxyIpPatterns: [/\.Header\.Get\(['"]X-Forwarded-For['"]\)/i, /\.Header\.Get\(['"]X-Real-IP['"]\)/i, /\bRemoteAddr\b/i],
    adminContext: /\b(admin|internal|debug|staff|superuser|production|authorize|permission|return\s+true)\b/i,
    strongAuth: /\b(requireAuth|authorize|isAdmin|session|jwt|middleware\.Auth)\b/i
  }
];

export function runCorrelationChecks(files: IndexedFile[], scannerResults: ScannerResult[]): ScannerResult[] {
  return [
    ...prototypePollutionToEtaRce(scannerResults),
    ...reachableDependencyFindings(files, scannerResults),
    ...weakHeaderAdminGates(files, "host"),
    ...weakHeaderAdminGates(files, "proxy-ip")
  ];
}

function prototypePollutionToEtaRce(scannerResults: ScannerResult[]): ScannerResult[] {
  const prototypeFindings = scannerResults.filter((result) => result.category === "prototype-pollution");
  if (!prototypeFindings.length) return [];
  const etaFindings = scannerResults.filter((result) => isEtaRceDependency(result));
  if (!etaFindings.length) return [];

  const proto = prototypeFindings[0];
  const eta = etaFindings[0];
  return [correlationResult({
    ruleId: "prototype-pollution-to-eta-rce",
    title: "Prototype pollution can enable Eta template RCE",
    category: "rce",
    severity: "critical",
    path: proto.path ?? eta.path,
    line: proto.startLine ?? eta.startLine,
    message: "Prototype pollution evidence exists in the application and dependency scanner evidence indicates vulnerable Eta template engine RCE/prototype pollution impact. Treat as a chained RCE path until disproven.",
    evidence: [
      { path: proto.path, line: proto.startLine, note: `${proto.scanner}/${proto.ruleId}: ${proto.title}` },
      { path: eta.path, line: eta.startLine, note: `${eta.scanner}/${eta.ruleId}: ${eta.title}` }
    ],
    related: [proto, eta],
    attackChain: {
      kind: "prototype-pollution-rce",
      impact: "Possible remote code execution through polluted template options.",
      confidence: "medium",
      steps: [
        "Attacker controls object keys reaching prototype pollution sink.",
        "Application uses vulnerable Eta dependency with RCE/prototype-pollution impact.",
        "Polluted template/runtime option may alter Eta rendering behavior."
      ],
      validation: [
        "Submit safe `__proto__`, `constructor`, and `prototype` keys to the cited source.",
        "Assert polluted option reaches Eta render path in a local test.",
        "Do not execute commands; stub dangerous process APIs when validating."
      ]
    }
  })];
}

function reachableDependencyFindings(files: IndexedFile[], scannerResults: ScannerResult[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const result of scannerResults.filter(isDependencyVulnerability)) {
    const reachability = analyzeDependencyReachability(files, result);
    const packageName = reachability.packageName;
    if (!packageName || packageName === "unknown") continue;
    const usage = reachability.vulnerableApiUsages.length ? reachability.vulnerableApiUsages : reachability.packageUsages;
    if (!usage.length) continue;
    const impact = dependencyImpact(result);
    const firstUsage = usage[0];
    const exactApi = reachability.vulnerableApiUsages[0]?.api;
    results.push(correlationResult({
      ruleId: exactApi ? `reachable-vulnerable-api-${safeRulePart(packageName)}-${safeRulePart(exactApi)}` : `reachable-${impact}-${safeRulePart(packageName)}`,
      title: exactApi ? `Reachable vulnerable API: ${packageName}.${exactApi}` : `Reachable vulnerable dependency: ${packageName}`,
      category: impact === "rce" ? "rce" : "dependency-reachability",
      severity: result.severity,
      path: firstUsage.path ?? result.path,
      line: firstUsage.line ?? result.startLine,
      message: exactApi
        ? `Dependency scanner reported ${packageName}, and indexed source calls vulnerable API ${exactApi}. Treat this as stronger reachability evidence than package presence alone.`
        : `Dependency scanner reported ${packageName}, and indexed source imports or references it. Treat exploitability as more likely than an unused transitive dependency.`,
      evidence: [
        { path: result.path, line: result.startLine, note: `${result.scanner}/${result.ruleId}: ${result.title}` },
        ...usage.slice(0, 4).map((item) => ({ path: item.path, line: item.line, note: `${item.api ? `${item.api}: ` : ""}${item.code}` }))
      ],
      related: [result],
      attackChain: {
        kind: exactApi ? "reachable-vulnerable-api" : "reachable-vulnerable-dependency",
        impact: exactApi
          ? `Vulnerable dependency API ${packageName}.${exactApi} appears used by application code.`
          : impact === "rce" ? "Possible reachable dependency RCE path." : "Vulnerable dependency appears used by application code.",
        confidence: exactApi ? "high" : "medium",
        steps: [
          `Dependency scanner reported vulnerable package ${packageName}.`,
          exactApi ? `Application source calls vulnerable API ${exactApi}.` : "Application source imports or references that package.",
          "Exploitability depends on whether vulnerable API and attacker-controlled data reach each other."
        ],
        validation: [
          "Open the usage evidence and identify the exact vulnerable API call.",
          "Check whether route/request/CLI input reaches that API.",
          "Add a safe regression test around the vulnerable API without exploiting external systems."
        ]
      }
    }));
  }
  return dedupe(results);
}

function weakHeaderAdminGates(files: IndexedFile[], kind: "host" | "proxy-ip"): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files) {
    const packs = matchingPacks(file);
    if (!packs.length) continue;
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      for (const pack of packs) {
        const patterns = kind === "host" ? pack.hostPatterns : pack.proxyIpPatterns;
        if (!patterns.some((pattern) => pattern.test(line))) continue;
        const window = nearby(lines, index, 10);
        if (!pack.adminContext.test(window)) continue;
        const hasStrongAuth = pack.strongAuth.test(window);
        const ruleId = kind === "host" ? "host-header-admin-gate" : "proxy-header-admin-gate";
        const title = kind === "host"
          ? "Host header controls admin or internal access gate"
          : "Proxy client IP header controls admin or internal access gate";
        const impact = kind === "host"
          ? "Possible admin/internal access bypass through spoofed Host or X-Forwarded-Host."
          : "Possible admin/internal access bypass through spoofed client IP forwarding headers.";
        results.push(correlationResult({
          ruleId,
          title: `${title} (${pack.name})`,
          category: "auth",
          severity: hasStrongAuth ? "medium" : "high",
          path: file.path,
          line: index + 1,
          message: `${title}. ${kind === "host" ? "Host headers" : "Proxy client IP headers"} are attacker-controlled unless overwritten by trusted proxy middleware/configuration.${hasStrongAuth ? " Strong auth also appears nearby; validate whether it dominates the header gate." : ""}`,
          evidence: [
            { path: file.path, line: index + 1, note: line.trim().slice(0, 220) }
          ],
          related: [],
          attackChain: {
            kind: kind === "host" ? "host-header-auth-bypass" : "proxy-header-auth-bypass",
            impact,
            confidence: hasStrongAuth ? "low" : "medium",
            steps: [
              `Application reads ${kind === "host" ? "Host/X-Forwarded-Host" : "X-Forwarded-For/client IP"} value.`,
              "Nearby control flow references admin/internal authorization context.",
              "If proxy does not normalize the header, attacker may spoof trusted value."
            ],
            validation: [
              `Send local request with spoofed ${kind === "host" ? "`Host` and `X-Forwarded-Host`" : "`X-Forwarded-For` and `X-Real-IP`"} headers.`,
              "Assert admin/internal route remains denied without authenticated role.",
              "Inspect reverse-proxy config for header overwrite and trusted proxy boundaries."
            ]
          }
        }));
      }
    }
  }
  return dedupe(results);
}

function isEtaRceDependency(result: ScannerResult): boolean {
  if (result.scanner !== "trivy" && result.scanner !== "osv-scanner") return false;
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, unknown> : {};
  const packageName = String(raw.PkgName ?? (raw.package as any)?.name ?? (raw.Package as any)?.Name ?? raw.name ?? result.title).toLowerCase();
  const text = `${packageName} ${result.ruleId} ${result.title} ${result.message} ${JSON.stringify(raw)}`.toLowerCase();
  return /\beta\b/.test(text) && /(rce|remote code execution|code execution|prototype pollution|template injection|ssti)/.test(text);
}

function isDependencyVulnerability(result: ScannerResult): boolean {
  if (result.scanner !== "trivy" && result.scanner !== "osv-scanner") return false;
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, unknown> : {};
  return Boolean(raw.VulnerabilityID || raw.id || /^CVE-\d{4}-\d+$/i.test(result.ruleId) || /^GHSA-/i.test(result.ruleId));
}

function dependencyImpact(result: ScannerResult): string {
  const text = `${result.ruleId} ${result.title} ${result.message} ${JSON.stringify(result.raw ?? {})}`.toLowerCase();
  if (/(rce|remote code execution|code execution|template injection|ssti|command injection)/.test(text)) return "rce";
  if (/prototype pollution/.test(text)) return "prototype-pollution";
  if (/xss|cross-site scripting/.test(text)) return "xss";
  if (/ssrf/.test(text)) return "ssrf";
  return "vulnerability";
}

function findPackageUsage(files: IndexedFile[], packageName: string): Evidence[] {
  const exact = escapeRegExp(packageName);
  const shortName = escapeRegExp(packageName.split("/").pop() ?? packageName);
  const slashAsNamespace = escapeRegExp(packageName).replace(/\\\//g, "\\\\");
  const patterns = [
    new RegExp(`from\\s+['"]${exact}['"]`),
    new RegExp(`import\\s+['"]${exact}['"]`),
    new RegExp(`require\\(\\s*['"]${exact}['"]\\s*\\)`),
    new RegExp(`(?:require|require_relative)\\s+['"]${shortName}['"]`),
    new RegExp(`(?:include|include_once|require|require_once)\\s*\\(?\\s*['"][^'"]*${shortName}[^'"]*['"]`),
    new RegExp(`use\\s+${slashAsNamespace}`, "i"),
    new RegExp(`\\bimport\\s+${shortName}\\b`, "i"),
    new RegExp(`\\bfrom\\s+${shortName}\\s+import\\b`, "i"),
    new RegExp(`\\bgem\\s+['"]${shortName}['"]`, "i"),
    new RegExp(`\\b${shortName}\\b`, "i")
  ];
  const evidence: Evidence[] = [];
  for (const file of files.filter((item) => !isManifestOnly(item.path) && isAuditableSource(item.path))) {
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!patterns.some((pattern) => pattern.test(line))) continue;
      evidence.push({ path: file.path, line: index + 1, note: `uses ${packageName}: ${line.trim().slice(0, 180)}` });
      if (evidence.length >= 8) return evidence;
    }
  }
  return evidence;
}

function correlationResult(input: {
  ruleId: string;
  title: string;
  category: string;
  severity: ScannerResult["severity"];
  path?: string;
  line?: number;
  message: string;
  evidence: Evidence[];
  related: ScannerResult[];
  attackChain?: AttackChain;
}): ScannerResult {
  return {
    scanner: "correlation",
    ruleId: input.ruleId,
    title: input.title,
    category: input.category,
    severity: input.severity,
    path: input.path,
    startLine: input.line,
    endLine: input.line,
    message: input.message,
    raw: {
      attackChain: input.attackChain,
      evidence: input.evidence,
      relatedFindings: input.related.map((item) => ({
        scanner: item.scanner,
        ruleId: item.ruleId,
        title: item.title,
        category: item.category,
        severity: item.severity,
        path: item.path,
        startLine: item.startLine
      }))
    }
  };
}

function matchingPacks(file: IndexedFile): FrameworkPack[] {
  return frameworkPacks.filter((pack) => pack.extensions.some((extension) => file.path.endsWith(extension)));
}

function isAuditableSource(filePath: string): boolean {
  return /\.(js|jsx|ts|tsx|mjs|cjs|py|php|rb|go|java|cs)$/.test(filePath);
}

function isManifestOnly(filePath: string): boolean {
  return /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|composer\.lock)$/i.test(filePath);
}

function safeRulePart(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "dependency";
}

function nearby(lines: string[], index: number, radius: number): string {
  return lines.slice(Math.max(0, index - radius), Math.min(lines.length, index + radius + 1)).join("\n");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function dedupe(results: ScannerResult[]): ScannerResult[] {
  const seen = new Set<string>();
  return results.filter((result) => {
    const key = `${result.ruleId}:${result.path}:${result.startLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
