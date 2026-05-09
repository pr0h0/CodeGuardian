import fs from "node:fs";
import path from "node:path";
import ignore from "ignore";
import { minimatch } from "minimatch";
import { DEFAULT_IGNORES } from "../config/defaults.js";

export interface IgnoreMatcher {
  ignores(relativePath: string, isDir?: boolean): boolean;
}

export function buildIgnoreMatcher(root: string, include: string[] = [], exclude: string[] = []): IgnoreMatcher {
  const ig = ignore().add(DEFAULT_IGNORES.map((entry) => `${entry}/`));
  const gitignore = path.join(root, ".gitignore");
  if (fs.existsSync(gitignore)) ig.add(fs.readFileSync(gitignore, "utf8"));
  return {
    ignores(relativePath: string, isDir = false): boolean {
      const normalized = relativePath.split(path.sep).join("/");
      if (include.length > 0 && !include.some((glob) => minimatch(normalized, glob, { dot: true }))) return true;
      if (exclude.some((glob) => minimatch(normalized, glob, { dot: true }))) return true;
      return ig.ignores(isDir ? `${normalized}/` : normalized);
    }
  };
}
