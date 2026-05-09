import fs from "node:fs";
import path from "node:path";
import { buildIgnoreMatcher } from "./ignoreRules.js";
import { relativePath } from "../utils/paths.js";

export interface WalkOptions {
  include?: string[];
  exclude?: string[];
  maxFiles?: number;
}

export function walkRepo(root: string, options: WalkOptions = {}): string[] {
  const matcher = buildIgnoreMatcher(root, options.include, options.exclude);
  const files: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      const rel = relativePath(root, absolute);
      if (matcher.ignores(rel, entry.isDirectory())) continue;
      if (entry.isDirectory()) stack.push(absolute);
      else if (entry.isFile()) {
        files.push(absolute);
        if (files.length >= (options.maxFiles ?? Number.MAX_SAFE_INTEGER)) return files;
      }
    }
  }
  return files.sort();
}
