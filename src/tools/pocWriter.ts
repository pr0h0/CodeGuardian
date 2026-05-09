import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";
import { isAllowedHost } from "./policy.js";

export function writePoc(outDir: string, target: string, allowedHosts: string[], name: string, body: string): string {
  if (!isAllowedHost(target, allowedHosts)) throw new Error("PoC target is not allowlisted");
  const dir = ensureDir(path.join(outDir, "pocs"));
  const file = path.join(dir, `${name.replace(/[^a-z0-9_-]/gi, "_")}.js`);
  fs.writeFileSync(file, `// target: ${target}\n// purpose: security validation PoC\n// risk level: medium\n// how to run: node ${path.basename(file)}\n// expected result: observe described behavior only against allowlisted target\n\n${body}\n`);
  return file;
}
