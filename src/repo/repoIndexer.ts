import fs from "node:fs";
import path from "node:path";
import { detectLanguage } from "./languageDetect.js";
import { walkRepo } from "./fileWalker.js";
import { extractSymbols } from "./symbolExtractor.js";
import { detectRoutes } from "./routeDetector.js";
import { extractImports } from "./importGraph.js";
import { insertChunk, insertEdge, insertFile, insertRoute, insertSymbol } from "../db/repositories.js";
import type { Db } from "../db/database.js";
import { sha256 } from "../utils/hashing.js";
import { lineCount, lineSlice } from "../utils/lineMap.js";
import { relativePath } from "../utils/paths.js";

export interface IndexedFile {
  path: string;
  absolutePath: string;
  language: string;
  content: string;
  lineCount: number;
}

export interface IndexOptions {
  maxFiles?: number;
  maxFileSize: number;
  include?: string[];
  exclude?: string[];
  cacheMap?: Map<string, string>; // path -> sha256 of previously indexed content
}

function isLikelyBinary(buffer: Buffer): boolean {
  return buffer.subarray(0, 8000).includes(0);
}

export function buildChunks(content: string, windowLines = 120, overlap = 20): Array<{ startLine: number; endLine: number; content: string }> {
  const total = lineCount(content);
  if (total <= windowLines) return [{ startLine: 1, endLine: Math.max(1, total), content }];
  const chunks = [];
  for (let start = 1; start <= total; start += windowLines - overlap) {
    const end = Math.min(total, start + windowLines - 1);
    chunks.push({ startLine: start, endLine: end, content: lineSlice(content, start, end) });
    if (end === total) break;
  }
  return chunks;
}

export function indexRepository(db: Db, scanId: string, repoPath: string, options: IndexOptions): IndexedFile[] {
  const files = walkRepo(repoPath, { maxFiles: options.maxFiles, include: options.include, exclude: options.exclude });
  const indexed: IndexedFile[] = [];
  for (const absolutePath of files) {
    const rel = relativePath(repoPath, absolutePath);
    const stat = fs.statSync(absolutePath);
    if (stat.size > options.maxFileSize) {
      insertFile(db, { scanId, path: rel, language: "unknown", sizeBytes: stat.size, sha256: "", lineCount: 0, indexed: false, skippedReason: "file exceeds max size" });
      continue;
    }
    const buffer = fs.readFileSync(absolutePath);
    if (isLikelyBinary(buffer)) {
      insertFile(db, { scanId, path: rel, language: "binary", sizeBytes: stat.size, sha256: sha256(buffer), lineCount: 0, indexed: false, skippedReason: "binary file" });
      continue;
    }
    const content = buffer.toString("utf8");
    const hash = sha256(content);
    // Skip full indexing if content hasn't changed since last scan
    if (options.cacheMap?.get(rel) === hash) {
      insertFile(db, { scanId, path: rel, language: "", sizeBytes: stat.size, sha256: hash, lineCount: 0, indexed: true, skippedReason: "cached, unchanged" });
      indexed.push({ path: rel, absolutePath, language: "", content: "", lineCount: 0 });
      continue;
    }
    const language = detectLanguage(rel, content.split(/\r?\n/, 1)[0] ?? "");
    const fileId = insertFile(db, { scanId, path: rel, language, sizeBytes: stat.size, sha256: hash, lineCount: lineCount(content), indexed: true });
    for (const chunk of buildChunks(content)) insertChunk(db, scanId, fileId, rel, chunk.startLine, chunk.endLine, chunk.content, sha256(chunk.content));
    for (const symbol of extractSymbols(content)) insertSymbol(db, { scanId, fileId, path: rel, name: symbol.name, kind: symbol.kind, startLine: symbol.startLine, endLine: symbol.endLine, signature: symbol.signature, exported: symbol.exported ? 1 : 0, metadataJson: "{}" });
    for (const route of detectRoutes(path.join("/", rel), content)) insertRoute(db, { scanId, fileId, method: route.method, routePath: route.routePath, handlerName: route.handlerName ?? null, startLine: route.startLine, endLine: route.endLine, frameworkGuess: route.frameworkGuess, metadataJson: "{}" });
    for (const imported of extractImports(content)) insertEdge(db, { scanId, fromType: "file", fromId: fileId, toType: "module", toId: null, edgeType: "imports", metadataJson: JSON.stringify({ path: rel, imported }) });
    indexed.push({ path: rel, absolutePath, language, content, lineCount: lineCount(content) });
  }
  return indexed;
}
