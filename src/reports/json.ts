import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

export function writeJsonReport(outDir: string, bundle: unknown, reportBase = "report"): string {
  ensureDir(outDir);
  const file = path.join(outDir, `${reportBase}.json`);
  fs.writeFileSync(file, JSON.stringify(bundle, null, 2));
  return file;
}
