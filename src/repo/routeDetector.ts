import { lineAtOffset } from "../utils/lineMap.js";

export interface RouteInfo {
  method: string;
  routePath: string;
  handlerName?: string;
  startLine: number;
  endLine: number;
  frameworkGuess: string;
}

export function detectRoutes(filePath: string, content: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  const regexes = [
    { framework: "express", regex: /\b(?:app|router)\.(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]/gi },
    { framework: "fastapi", regex: /@app\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/gi },
    { framework: "flask", regex: /@app\.route\s*\(\s*['"]([^'"]+)['"][^)]*methods\s*=\s*\[?['"]?([A-Z]+)/gi },
    { framework: "spring", regex: /@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*['"]([^'"]+)['"]/g },
    { framework: "rails", regex: /^\s*(get|post|put|patch|delete|match)\s+['"]([^'"]+)['"]/gim },
    { framework: "sinatra", regex: /^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]\s+do\b/gim },
    { framework: "laravel", regex: /Route::(get|post|put|patch|delete|any|match)\s*\(\s*['"]([^'"]+)['"]/g },
    { framework: "php", regex: /\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*={2,3}\s*['"]([A-Z]+)['"][\s\S]{0,240}?\$_SERVER\s*\[\s*['"]REQUEST_URI['"]\s*\]/g }
  ];
  for (const item of regexes) {
    for (const match of content.matchAll(item.regex)) {
      const method = item.framework === "flask" ? match[2] : match[1];
      const routePath = item.framework === "flask" ? match[1] : item.framework === "php" ? filePath : match[2];
      const line = lineAtOffset(content, match.index ?? 0);
      routes.push({ method: method.toUpperCase().replace("MAPPING", ""), routePath, startLine: line, endLine: line, frameworkGuess: item.framework });
    }
  }
  if (/(^|\/)(routes\/web|routes\/api)\.php$/.test(filePath)) {
    routes.push({ method: "ANY", routePath: filePath, startLine: 1, endLine: 1, frameworkGuess: "laravel" });
  }
  if (/(^|\/)config\/routes\.rb$/.test(filePath)) {
    routes.push({ method: "ANY", routePath: filePath, startLine: 1, endLine: 1, frameworkGuess: "rails" });
  }
  if (/\/pages\/api\/|\/app\/api\//.test(filePath)) {
    routes.push({ method: "ANY", routePath: filePath.replace(/^.*\/(?:pages|app)\/api/, "/api").replace(/\.[^.]+$/, ""), startLine: 1, endLine: 1, frameworkGuess: "nextjs" });
  }
  return routes;
}
