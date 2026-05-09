import { lineAtOffset } from "../utils/lineMap.js";

export interface SymbolInfo {
  name: string;
  kind: string;
  startLine: number;
  endLine: number;
  signature: string;
  exported: boolean;
}

const patterns: Array<{ kind: string; regex: RegExp; nameGroup?: number }> = [
  { kind: "class", regex: /^\s*(export\s+)?class\s+([A-Za-z_$][\w$]*)/gm, nameGroup: 2 },
  { kind: "function", regex: /^\s*(export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm, nameGroup: 2 },
  { kind: "function", regex: /^\s*(export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/gm, nameGroup: 2 },
  { kind: "function", regex: /^\s*def\s+([A-Za-z_]\w*)\s*\(/gm, nameGroup: 1 },
  { kind: "class", regex: /^\s*class\s+([A-Za-z_]\w*)/gm, nameGroup: 1 },
  { kind: "function", regex: /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/gm, nameGroup: 1 },
  { kind: "type", regex: /^\s*type\s+([A-Za-z_]\w*)\s+/gm, nameGroup: 1 },
  { kind: "function", regex: /^\s*(?:public|private|protected|static|\s)*[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{/gm, nameGroup: 1 },
  { kind: "module", regex: /^\s*module\s+([A-Za-z_:]\w*)/gm, nameGroup: 1 },
  { kind: "function", regex: /^\s*function\s+([A-Za-z_]\w*)\s*\(/gm, nameGroup: 1 }
];

export function extractSymbols(content: string): SymbolInfo[] {
  const symbols: SymbolInfo[] = [];
  for (const { kind, regex, nameGroup = 1 } of patterns) {
    for (const match of content.matchAll(regex)) {
      const line = lineAtOffset(content, match.index ?? 0);
      symbols.push({
        name: match[nameGroup] ?? "anonymous",
        kind,
        startLine: line,
        endLine: line,
        signature: match[0].trim(),
        exported: /\bexport\b/.test(match[0])
      });
    }
  }
  return symbols.sort((a, b) => a.startLine - b.startLine);
}
