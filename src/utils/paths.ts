import path from "node:path";
import { mkdirSync } from "node:fs";

export function ensureDir(dir: string): string {
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function relativePath(root: string, file: string): string {
  return path.relative(root, file).split(path.sep).join("/");
}

export function isInside(parent: string, child: string): boolean {
  const rel = path.relative(path.resolve(parent), path.resolve(child));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}
