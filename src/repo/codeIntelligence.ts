import ts from "typescript";
import type { RouteInfo } from "./routeDetector.js";
import { detectRoutes } from "./routeDetector.js";
import { extractImports } from "./importGraph.js";
import { extractSymbols, type SymbolInfo } from "./symbolExtractor.js";

export interface CodeAnalysis {
  imports: string[];
  symbols: SymbolInfo[];
  routes: RouteInfo[];
}

const jsTsExtensions = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]);
const httpMethods = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

export function analyzeCode(filePath: string, content: string): CodeAnalysis {
  if (!isJavaScriptOrTypeScript(filePath)) {
    return {
      imports: extractImports(content),
      symbols: extractSymbols(content),
      routes: detectRoutes(routeDetectionPath(filePath), content)
    };
  }
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true, scriptKind(filePath));
  const parser = parseJavaScriptLike(sourceFile);
  return {
    imports: mergeStrings(parser.imports, extractImports(content)),
    symbols: dedupeSymbols([...parser.symbols, ...extractSymbols(content)]),
    routes: dedupeRoutes([...parser.routes, ...detectRoutes(routeDetectionPath(filePath), content)])
  };
}

function parseJavaScriptLike(sourceFile: ts.SourceFile): CodeAnalysis {
  const imports: string[] = [];
  const symbols: SymbolInfo[] = [];
  const routes: RouteInfo[] = [];

  const visit = (node: ts.Node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const [specifier] = node.arguments;
      if (specifier && ts.isStringLiteralLike(specifier)) imports.push(specifier.text);
    }
    if (ts.isFunctionDeclaration(node) && node.name) {
      symbols.push(symbolFromNode(sourceFile, node, "function", node.name.text, isExported(node), node.getText(sourceFile).split(/\r?\n/, 1)[0] ?? ""));
    }
    if (ts.isClassDeclaration(node) && node.name) {
      symbols.push(symbolFromNode(sourceFile, node, "class", node.name.text, isExported(node), node.getText(sourceFile).split(/\r?\n/, 1)[0] ?? ""));
    }
    if (ts.isVariableStatement(node)) {
      const exported = isExported(node);
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
        if (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)) {
          symbols.push(symbolFromNode(sourceFile, declaration, "function", declaration.name.text, exported, declaration.getText(sourceFile).split(/\r?\n/, 1)[0] ?? ""));
        }
        if (ts.isClassExpression(declaration.initializer)) {
          symbols.push(symbolFromNode(sourceFile, declaration, "class", declaration.name.text, exported, declaration.getText(sourceFile).split(/\r?\n/, 1)[0] ?? ""));
        }
      }
    }
    const route = routeFromCall(sourceFile, node);
    if (route) routes.push(route);
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return { imports: mergeStrings(imports), symbols: dedupeSymbols(symbols), routes: dedupeRoutes(routes) };
}

function routeFromCall(sourceFile: ts.SourceFile, node: ts.Node): RouteInfo | undefined {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
  const method = node.expression.name.text.toLowerCase();
  if (!httpMethods.has(method)) return undefined;
  const [routeArg, handlerArg] = node.arguments;
  if (!routeArg || !ts.isStringLiteralLike(routeArg)) return undefined;
  const line = lineOf(sourceFile, node);
  return {
    method: method.toUpperCase(),
    routePath: routeArg.text,
    handlerName: handlerArg && ts.isIdentifier(handlerArg) ? handlerArg.text : undefined,
    startLine: line,
    endLine: line,
    frameworkGuess: "express"
  };
}

function symbolFromNode(sourceFile: ts.SourceFile, node: ts.Node, kind: string, name: string, exported: boolean, signature: string): SymbolInfo {
  const line = lineOf(sourceFile, node);
  return { name, kind, startLine: line, endLine: line, signature: signature.trim(), exported };
}

function lineOf(sourceFile: ts.SourceFile, node: ts.Node): number {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function isExported(node: ts.Node): boolean {
  return Boolean(ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
}

function isJavaScriptOrTypeScript(filePath: string): boolean {
  return jsTsExtensions.has(extension(filePath));
}

function scriptKind(filePath: string): ts.ScriptKind {
  const ext = extension(filePath);
  if (ext === ".tsx") return ts.ScriptKind.TSX;
  if (ext === ".jsx") return ts.ScriptKind.JSX;
  if (ext === ".ts") return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function extension(filePath: string): string {
  const match = filePath.toLowerCase().match(/\.[^.]+$/);
  return match?.[0] ?? "";
}

function routeDetectionPath(filePath: string): string {
  const normalized = filePath.replaceAll("\\", "/");
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function mergeStrings(...groups: string[][]): string[] {
  return [...new Set(groups.flat())];
}

function dedupeSymbols(symbols: SymbolInfo[]): SymbolInfo[] {
  const seen = new Set<string>();
  return symbols.filter((symbol) => {
    const key = `${symbol.kind}:${symbol.name}:${symbol.startLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => a.startLine - b.startLine || a.name.localeCompare(b.name));
}

function dedupeRoutes(routes: RouteInfo[]): RouteInfo[] {
  const seen = new Set<string>();
  return routes.filter((route) => {
    const key = `${route.frameworkGuess}:${route.method}:${route.routePath}:${route.startLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => a.startLine - b.startLine || a.routePath.localeCompare(b.routePath));
}
