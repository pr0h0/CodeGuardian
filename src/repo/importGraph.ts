export function extractImports(content: string): string[] {
  const imports = new Set<string>();
  const regexes = [
    /\bimport\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /^\s*from\s+([\w.]+)\s+import\s+/gm,
    /^\s*import\s+([\w.]+)/gm,
    /^\s*use\s+([^;]+);/gm,
    /\b(?:require|require_once|include|include_once)\s*\(?\s*['"]([^'"]+)['"]\s*\)?/g,
    /^\s*(?:require|require_relative)\s+['"]([^'"]+)['"]/gm,
    /^\s*#include\s+[<"]([^>"]+)[>"]/gm
  ];
  for (const regex of regexes) for (const match of content.matchAll(regex)) imports.add(match[1]);
  return [...imports];
}
