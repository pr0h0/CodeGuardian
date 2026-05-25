import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import { detectRoutes } from "../repo/routeDetector.js";
import { classifyFileRole, isReusableOrGeneratedRole } from "../repo/fileRole.js";
import type { ScannerResult } from "./types.js";

interface SourcePatternRule {
  id: string;
  title: string;
  category: string;
  severity: ScannerResult["severity"];
  test: (file: IndexedFile, lines: string[], index: number) => boolean;
  message: (line: string) => string;
}

const sourceRules: SourcePatternRule[] = [
  {
    id: "source-xxe-unsafe-parser",
    title: "XML parser expands entities for user-controlled XML",
    category: "xxe",
    severity: "high",
    test: (file, lines, index) => {
      const window = windowText(lines, index, 4);
      return /(parseXml|DOMParser|SAXParser|DocumentBuilderFactory|libxml|xml2js|lxml|etree)/i.test(lines[index] ?? "")
        && /(parseXml|DOMParser|SAXParser|DocumentBuilderFactory|libxml|xml2js|lxml|etree)/i.test(window)
        && /(noent\s*:\s*true|resolve_entities\s*=\s*true|external-general-entities|load-external-dtd|expandEntityReferences\s*\(\s*true)/i.test(window)
        && /(req\.|request\.|file\.buffer|body|params|query|\$_(POST|FILES|REQUEST)|input)/i.test(file.content);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-zip-slip-entry-path",
    title: "Archive entry path is written without base-directory enforcement",
    category: "file-upload",
    severity: "high",
    test: (_file, lines, index) => {
      const window = windowText(lines, index, 8);
      return /(entry\.path|createWriteStream|writeFile|extract|pipe)/i.test(lines[index] ?? "")
        && /(entry\.path|zipEntry\.entryName|fileName|filename)/i.test(window)
        && /(unzipper|adm-zip|yauzl|ZipFile|extract|archive)/i.test(window)
        && /(createWriteStream|writeFile|copyFile|extract|pipe)/i.test(window)
        && !/(normalize|realpath|startsWith|basename|path\.isAbsolute|safeJoin|validate)/i.test(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-nosql-where-concat",
    title: "NoSQL query uses string-built $where predicate",
    category: "injection",
    severity: "high",
    test: (_file, lines, index) => /\$where\s*:\s*['"`][^'"`]*['"`]\s*\+/.test(lines[index] ?? ""),
    message: (line) => line.trim()
  },
  {
    id: "source-open-redirect-variable",
    title: "Redirect uses variable target that needs strict allowlist review",
    category: "open-redirect",
    severity: "medium",
    test: (_file, lines, index) => {
      const window = windowText(lines, index, 6);
      const line = lines[index] ?? "";
      const target = redirectTargetExpression(line);
      return Boolean(target)
        && isRequestControlledExpression(target!, window)
        && !isSafeRedirectTarget(target!, window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-session-regenerate-missing",
    title: "Login assigns a session principal without regenerating the session id",
    category: "auth",
    severity: "high",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = functionWindowText(lines, index, 18);
      return /\b(req|request)\.session\.(user|admin|account|principal)\s*=/.test(line)
        && /(login|signin|password|compare|findOne|findBy|authenticate)/i.test(window)
        && !/\.session\.regenerate\s*\(/i.test(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-rate-limiter-disabled",
    title: "Rate limiter appears disabled on routed requests",
    category: "auth",
    severity: "medium",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = windowText(lines, index, 3);
      return /^\s*\/\/\s*if\s*\(\s*this\.limiter\s*\)\s*handlers\.unshift\s*\(\s*this\.limiter\s*\)/i.test(line)
        || (/TODO:?\s+.*\blimiter\b/i.test(line)
          && /this\.limiter|rateLimit|handlers\.unshift/i.test(window)
          && !lines.slice(index + 1, Math.min(lines.length, index + 4)).some((nextLine) => /^\s*\/\/\s*if\s*\(\s*this\.limiter\s*\)\s*handlers\.unshift\s*\(\s*this\.limiter\s*\)/i.test(nextLine)));
    },
    message: (line) => line.trim()
  },
  {
    id: "source-request-url-to-service-fetch",
    title: "Request-controlled URL is passed to an outbound fetch helper",
    category: "ssrf",
    severity: "high",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = functionWindowText(lines, index, 14);
      return /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:req|request)\.(?:body|query|params)\.(?:url|uri|href|link|target)\b/i.test(line)
        && /\b(getImage|getUrl|fetchUrl|HttpService\.get|ScraperService\.getImage|axios\.get|fetch|request)\s*\(\s*[A-Za-z_$][\w$]*/i.test(window)
        && !hasUrlSafetyGuard(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-ssrf-wrapper-unvalidated-url",
    title: "Outbound request wrapper accepts arbitrary URL input without validation",
    category: "ssrf",
    severity: "high",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = windowText(lines, index, 20);
      const sinkWindow = lines.slice(index, Math.min(lines.length, index + 3)).join("\n");
      const parameter = outboundWrapperParameter(window);
      return Boolean(parameter)
        && /\b(?:fetch|axios\.(?:get|post|request)|instance\.(?:get|post|request)|request\s*\(|http\.get|https\.get)\s*\(/i.test(sinkWindow)
        && new RegExp(`\\b(?:fetch|axios\\.(?:get|post|request)|instance\\.(?:get|post|request)|request|http\\.get|https\\.get)\\s*\\(\\s*${escapeRegExp(parameter!)}\\b`, "i").test(sinkWindow)
        && /\b(?:fetch|axios\.(?:get|post|request)|instance\.(?:get|post|request)|request\s*\(|http\.get|https\.get)\s*\(/i.test(line)
        && !hasUrlSafetyGuard(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-next-path-proxy-fetch",
    title: "Next route proxies request pathname to fetch without path validation",
    category: "ssrf",
    severity: "high",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = functionWindowText(lines, index, 14);
      return /\bfetch\s*\(\s*[A-Za-z_$][\w$]*/i.test(line)
        && /request\.nextUrl\.pathname/i.test(window)
        && /\bprepareUrl\s*\(/i.test(window)
        && !/(decodeURIComponent|path\.normalize|basename|\bstartsWith\b|\ballowlist\b|\ballowed\b|\bvalidate(?:Url|URL)?\b|\bsafePath\b|\breject\b|URLPattern)/i.test(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-url-join-collapse-normalization",
    title: "URL builder collapses slash characters instead of validating URL path boundaries",
    category: "ssrf",
    severity: "medium",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      return /\.replace\s*\(\s*\/\[\/\/\]\+\/[gimyus]*\s*,\s*['"]\/['"]\s*\)/i.test(line);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-request-controlled-object-id",
    title: "Request-controlled object identifier is used without an ownership check",
    category: "authorization",
    severity: "high",
    test: (_file, lines, index) => {
      const line = lines[index] ?? "";
      const window = functionWindowText(lines, index, 18);
      return /(findOne|findByPk|findById|findUnique|findFirst|update|updateOne|delete|deleteOne|destroy|remove|where)\s*\(/i.test(line)
        && hasRequestControlledObjectId(window)
        && !hasServerSideOwnershipGuard(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-mass-assignment-user-fields",
    title: "Request body is assigned into a model update without field allowlisting",
    category: "business-logic",
    severity: "medium",
    test: (_file, lines, index) => {
      const window = functionWindowText(lines, index, 12);
      return /(update|create|assign|merge|save)\s*\(/i.test(lines[index] ?? "")
        && /(req|request)\.(body|json)\b/i.test(window)
        && /(userId|ownerId|tenantId|role|isAdmin|price|quantity|discount|balance|credit|status)\b/i.test(window)
        && !/(pick|omit|allowlist|whitelist|schema|validate|zod|joi|yup|permitted|permit\()/i.test(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-price-quantity-from-client",
    title: "Business-critical price or quantity field is trusted from request data",
    category: "business-logic",
    severity: "medium",
    test: (_file, lines, index) => {
      const window = functionWindowText(lines, index, 12);
      return /(checkout|order|payment|basket|cart|coupon|discount|price|quantity)/i.test(window)
        && /(req|request)\.(body|query|params)\.(price|amount|total|quantity|qty|discount|coupon|role|isAdmin)\b/i.test(window)
        && /(create|update|save|charge|checkout|purchase|add|apply|calculate)/i.test(lines[index] ?? "")
        && !/(allowlist|whitelist|allowed|sameOrigin|URLPattern|startsWith\(['"]\/)/i.test(window);
    },
    message: (line) => line.trim()
  },
  {
    id: "source-file-extension-validation",
    title: "File upload validation relies on client-controlled filename or MIME metadata",
    category: "file-upload",
    severity: "medium",
    test: (_file, lines, index) => {
      const window = windowText(lines, index, 5);
      return /(originalname|mimetype|contentType|filename)/i.test(window)
        && /(substr|split|endsWith|includes|match|extension|extname)/i.test(window)
        && /(upload|file|multer|multipart)/i.test(window);
    },
    message: (line) => line.trim()
  }
];

const sensitiveRoutePattern = /\/(admin|internal|debug|metrics|logs?|export|users?|accounts?|basket|cart|orders?|checkout|payment|invoice|profile|settings|token|session|password|coupon|review|feedback|deluxe)\b/i;
const guardPattern = /(requireAuth|isAuthenticated|isAuthorized|authorize|authenticated|security\.isAuthorized|appendUserId|csrf|permission|policy|role|guard|middleware)/i;

export function runSourcePatternChecks(files: IndexedFile[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files.filter(isSourcePatternCandidate)) {
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      for (const rule of sourceRules) {
        if (!rule.test(file, lines, index)) continue;
        results.push(result(rule, file.path, index + 1, rule.message(line)));
      }
    }
    results.push(...routeGuardFindings(file, lines));
    results.push(...authLifecycleFindings(file, lines));
  }
  return dedupeResults(results);
}

function routeGuardFindings(file: IndexedFile, lines: string[]): ScannerResult[] {
  const findings: ScannerResult[] = [];
  for (const route of detectRoutes(file.path, file.content)) {
    const method = route.method.toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "ALL", "USE"].includes(method)) continue;
    if (!sensitiveRoutePattern.test(route.routePath)) continue;
    const start = Math.max(1, route.startLine - 1);
    const end = Math.min(lines.length, route.startLine + 3);
    const nearby = lines.slice(start - 1, end).join("\n");
    if (guardPattern.test(nearby)) continue;
    findings.push(result({
      id: "source-sensitive-route-without-guard",
      title: "Sensitive route lacks an obvious inline authentication or authorization guard",
      category: /(basket|cart|order|checkout|payment|coupon|review|feedback|deluxe)/i.test(route.routePath) ? "business-logic" : "authorization",
      severity: /(admin|internal|export|token|password|payment|checkout)/i.test(route.routePath) ? "high" : "medium"
    }, file.path, route.startLine, `${method} ${route.routePath}`));
  }
  return findings;
}

function authLifecycleFindings(file: IndexedFile, lines: string[]): ScannerResult[] {
  const findings: ScannerResult[] = [];
  const content = lines.join("\n");
  const loginMessages = [...content.matchAll(/message\s*:\s*(?:\{[^}]*content\s*:\s*)?['"`]([^'"`]+)['"`]/gi)]
    .map((match) => String(match[1] ?? "").toLowerCase());
  if (loginMessages.some((message) => /user .*not found|unknown user|no such user/.test(message))
    && loginMessages.some((message) => /invalid password|wrong password|bad password/.test(message))) {
    const line = firstLineMatching(lines, /user .*not found|unknown user|no such user/i);
    findings.push(result({
      id: "source-login-distinct-failure-messages",
      title: "Login flow exposes distinct username and password failure messages",
      category: "auth",
      severity: "medium"
    }, file.path, line, lines[line - 1]?.trim() || "distinct login failure messages"));
  }

  for (const route of detectRoutes(file.path, file.content)) {
    if (route.method.toUpperCase() !== "GET") continue;
    if (!/(logout|signout|delete|destroy|revoke|disconnect|deactivate)/i.test(route.routePath)) continue;
    const nearby = windowText(lines, route.startLine - 1, 4);
    if (/(csrf|sameSite|idempotent|safeLogout)/i.test(nearby)) continue;
    findings.push(result({
      id: "source-state-changing-get-logout",
      title: "State-changing logout route uses GET",
      category: "auth",
      severity: "medium"
    }, file.path, route.startLine, `${route.method} ${route.routePath}`));
  }

  return findings;
}

function result(rule: Pick<SourcePatternRule, "id" | "title" | "category" | "severity">, filePath: string, line: number, message: string): ScannerResult {
  return {
    scanner: "source-patterns",
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    path: filePath,
    startLine: line,
    endLine: line,
    message: message.slice(0, 300),
    raw: {
      description: "Static source-pattern seed for AI/developer review. The pattern is framework-generic and should be validated before remediation.",
      confidence: "medium",
      sourceLine: message
    }
  };
}

function windowText(lines: string[], index: number, radius: number): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(lines.length, index + radius + 1);
  return lines.slice(start, end).join("\n");
}

function functionWindowText(lines: string[], index: number, radius: number): string {
  let start = Math.max(0, index - radius);
  let end = Math.min(lines.length, index + radius + 1);
  for (let i = index; i >= start; i--) {
    if (/\b(function|async function|=>)\b|[{]\s*$/.test(lines[i] ?? "")) {
      start = i;
      break;
    }
  }
  for (let i = index; i < end; i++) {
    if (/^\s*}\)?;?\s*$/.test(lines[i] ?? "")) {
      end = i + 1;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function redirectTargetExpression(line: string): string | undefined {
  const redirect = line.match(/\b(?:res\.redirect|reply\.redirect|redirect_to|redirect)\s*\(\s*([^),;]+)/i);
  if (redirect?.[1]) return redirect[1].trim();
  const header = line.match(/header\s*\(\s*['"]Location:\s*\$\{?([^}'"]+)/i);
  if (header?.[1]) return header[1].trim();
  const location = line.match(/\blocation\.href\s*=\s*([^;]+)/i);
  if (location?.[1]) return location[1].trim();
  return undefined;
}

function isRequestControlledExpression(expression: string, window: string): boolean {
  if (/(req|request)\.(query|params|body|headers|url|originalUrl)|\$_(GET|POST|REQUEST|SERVER)|params\[|request\.(args|form|json)/i.test(expression)) return true;
  const variable = expression.match(/^[A-Za-z_$][\w$]*/)?.[0];
  if (!variable) return false;
  const assignment = new RegExp(`\\b(?:const|let|var)\\s+${escapeRegExp(variable)}\\s*=\\s*([^;\\n]+)`, "i");
  const assignmentValue = window.match(assignment)?.[1] ?? "";
  return /(req|request)\.(query|params|body|headers|url|originalUrl)|\$_(GET|POST|REQUEST|SERVER)|params\[|request\.(args|form|json)/i.test(assignmentValue);
}

function isSafeRedirectTarget(expression: string, window: string): boolean {
  if (/^['"]\/(?!\/)/.test(expression.trim())) return true;
  return /(allowlist|whitelist|allowedRedirect|allowedOrigins|sameOrigin|URLPattern|new URL\([^)]*baseUrl|startsWith\(['"]\/|isLocalUrl|safeRedirect|validateRedirect)/i.test(window);
}

function hasRequestControlledObjectId(window: string): boolean {
  return /(req|request)\.(params|body|query)\.(userId|user_id|ownerId|owner_id|tenantId|tenant_id|accountId|account_id|customerId|customer_id|organizationId|organisationId|orgId|basketId|cartId|orderId|paymentId|invoiceId|profileId|reviewId|id)\b|params\[['"](userId|user_id|ownerId|tenantId|accountId|customerId|orgId|basketId|cartId|orderId|paymentId|invoiceId|profileId|reviewId|id)['"]\]/i.test(window);
}

function hasServerSideOwnershipGuard(window: string): boolean {
  if (/(authorize|authorize!|policy|can\?|requireOwner|requirePermission|isAuthorized|appendUserId|security\.isAuthorized|security\.authenticatedUsers|ownership|belongsTo|scopeToCurrentUser|current_user)/i.test(window)) return true;
  const hasPrincipal = /(req\.user|request\.user|res\.locals\.user|ctx\.user|context\.user|session\.user|currentUser|current_user|principal|auth\.user)/i.test(window);
  if (!hasPrincipal) return false;
  return /(===|!==|==|!=|userId\s*:\s*(req\.user|request\.user|res\.locals\.user|ctx\.user|context\.user|session\.user|currentUser|current_user|principal|auth\.user)\.id|ownerId\s*:\s*(req\.user|request\.user|res\.locals\.user|ctx\.user|context\.user|session\.user|currentUser|current_user|principal|auth\.user)\.id|tenantId\s*:\s*(req\.user|request\.user|res\.locals\.user|ctx\.user|context\.user|session\.user|currentUser|current_user|principal|auth\.user)\.tenantId)/i.test(window);
}

function hasUrlSafetyGuard(window: string): boolean {
  return /(allowlist|whitelist|allowedHost|allowedOrigin|URLPattern|validateUrl|validateURL|safeUrl|safeURL|isPrivateIp|privateIp|blockInternal|dns\.lookup|net\.isIP|ipaddr|new URL\(|hostname|protocol|startsWith\(['"]https?:\/\/[^'"]+['"]\))/i.test(window);
}

function outboundWrapperParameter(window: string): string | undefined {
  const patterns = [
    /(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(\s*([A-Za-z_$][\w$]*)/i,
    /(?:^|\n)\s*(?:(?:public|private|protected|static|async)\s+)*(?:get|post|raw|request|getImage|getUrl|fetchUrl)\s*(?:<[^>\n]+>)?\s*\(\s*([A-Za-z_$][\w$]*)/i,
    /(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?\(\s*([A-Za-z_$][\w$]*)/i
  ];
  for (const pattern of patterns) {
    const match = window.match(pattern);
    if (match?.[1]) return match[1];
  }
  return undefined;
}

function firstLineMatching(lines: string[], pattern: RegExp): number {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? 1 : index + 1;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isSourceLike(file: IndexedFile): boolean {
  return /\.(js|jsx|mjs|cjs|ts|tsx|py|php|rb|go|java|cs|vue|svelte)$/i.test(file.path) || sourceLikeLanguage(file.language);
}

function isSourcePatternCandidate(file: IndexedFile): boolean {
  if (!isSourceLike(file)) return false;
  return !isReusableOrGeneratedRole(classifyFileRole(file.path, file.language));
}

function sourceLikeLanguage(language: string): boolean {
  return ["javascript", "typescript", "python", "php", "ruby", "go", "java", "csharp"].includes(language.toLowerCase());
}

function dedupeResults(results: ScannerResult[]): ScannerResult[] {
  const seen = new Set<string>();
  return results.filter((item) => {
    const key = `${item.ruleId}:${path.posix.normalize(item.path ?? "")}:${item.startLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
