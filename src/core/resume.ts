import fs from "node:fs";
import path from "node:path";
import { walkRepo } from "../repo/fileWalker.js";
import { sha256 } from "../utils/hashing.js";

export type ResumeStage = "index" | "scanner-results" | "ai" | "reports";

export interface ScanWorkspace {
  name: string;
  dir: string;
  resume: boolean;
}

export interface WorkspaceStageSummary {
  stage: string;
  updatedAt: string;
  fingerprint: string;
}

export interface WorkspaceSummary {
  name: string;
  dir: string;
  exists: boolean;
  status: "empty" | "ready" | "corrupt";
  stages: WorkspaceStageSummary[];
  error?: string;
}

interface SnapshotEnvelope<T> {
  version: 1;
  stage: ResumeStage;
  fingerprint: string;
  createdAt: string;
  data: T;
}

interface WorkspaceState {
  version: 1;
  name: string;
  updatedAt: string;
  stages: Record<string, WorkspaceStageSummary>;
}

export function resolveScanWorkspace(repoPath: string, input: { workspace?: string; resume?: boolean | string; options?: unknown } = {}): ScanWorkspace {
  const resumeName = typeof input.resume === "string" ? input.resume : undefined;
  const name = sanitizeWorkspaceName(resumeName ?? input.workspace ?? defaultWorkspaceName(repoPath, input.options));
  return {
    name,
    dir: path.join(repoPath, ".codeguardian", "workspaces", name),
    resume: Boolean(input.resume)
  };
}

export function buildSourceTreeFingerprint(repoPath: string, options: { include?: string[]; exclude?: string[]; maxFiles?: number } = {}): string {
  const files = walkRepo(repoPath, options);
  const entries = files.map((file) => {
    const stat = fs.statSync(file);
    return `${path.relative(repoPath, file).replaceAll("\\", "/")}:${stat.size}:${Math.round(stat.mtimeMs)}`;
  });
  return sha256(JSON.stringify(entries));
}

export function buildResumeFingerprint(input: { repoPath: string; options: Record<string, unknown>; projectConfig: unknown; sourceTreeFingerprint?: string }): string {
  const relevantOptions = stableObjectWithout(input.options, [
    "out",
    "format",
    "verbose",
    "ci",
    "failOn",
    "baseline",
    "workspace",
    "resume"
  ]);
  return sha256(stableJson({
    repoPath: path.resolve(input.repoPath),
    options: relevantOptions,
    projectConfig: input.projectConfig,
    sourceTreeFingerprint: input.sourceTreeFingerprint ?? null
  }));
}

export function writeStageSnapshot<T>(workspace: ScanWorkspace, stage: ResumeStage, fingerprint: string, data: T): void {
  fs.mkdirSync(workspace.dir, { recursive: true });
  const envelope: SnapshotEnvelope<T> = {
    version: 1,
    stage,
    fingerprint,
    createdAt: new Date().toISOString(),
    data
  };
  fs.writeFileSync(snapshotPath(workspace, stage), `${JSON.stringify(envelope, null, 2)}\n`);
  updateWorkspaceState(workspace, stage, envelope.createdAt, fingerprint);
}

export function readStageSnapshot<T>(workspace: ScanWorkspace, stage: ResumeStage, fingerprint: string, options: { strict?: boolean } = {}): T | undefined {
  const file = snapshotPath(workspace, stage);
  if (!fs.existsSync(file)) return undefined;
  try {
    const envelope = JSON.parse(fs.readFileSync(file, "utf8")) as SnapshotEnvelope<T>;
    if (envelope.version !== 1 || envelope.stage !== stage) throw new Error(`invalid ${stage} snapshot envelope`);
    if (envelope.fingerprint !== fingerprint) throw new Error(`workspace snapshot fingerprint mismatch for ${stage}`);
    return envelope.data;
  } catch (error) {
    if (options.strict) throw error;
    return undefined;
  }
}

export function listScanWorkspaces(repoPath: string): WorkspaceSummary[] {
  const root = path.join(repoPath, ".codeguardian", "workspaces");
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => summarizeScanWorkspace(repoPath, entry.name))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function summarizeScanWorkspace(repoPath: string, workspaceName: string): WorkspaceSummary {
  const workspace = resolveScanWorkspace(repoPath, { workspace: workspaceName });
  if (!fs.existsSync(workspace.dir)) {
    return { name: workspace.name, dir: workspace.dir, exists: false, status: "empty", stages: [] };
  }
  const stateFile = path.join(workspace.dir, "state.json");
  if (!fs.existsSync(stateFile)) {
    return { name: workspace.name, dir: workspace.dir, exists: true, status: "empty", stages: [] };
  }
  try {
    const state = JSON.parse(fs.readFileSync(stateFile, "utf8")) as WorkspaceState;
    return {
      name: workspace.name,
      dir: workspace.dir,
      exists: true,
      status: "ready",
      stages: Object.values(state.stages).sort((a, b) => a.stage.localeCompare(b.stage))
    };
  } catch (error) {
    return {
      name: workspace.name,
      dir: workspace.dir,
      exists: true,
      status: "corrupt",
      stages: [],
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function defaultWorkspaceName(repoPath: string, options: unknown): string {
  const base = path.basename(path.resolve(repoPath)) || "repo";
  return `${base}-${sha256(stableJson({ repoPath: path.resolve(repoPath), options })).slice(0, 10)}`;
}

function sanitizeWorkspaceName(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "default";
}

function snapshotPath(workspace: ScanWorkspace, stage: ResumeStage): string {
  return path.join(workspace.dir, `${stage}.json`);
}

function updateWorkspaceState(workspace: ScanWorkspace, stage: ResumeStage, updatedAt: string, fingerprint: string): void {
  const stateFile = path.join(workspace.dir, "state.json");
  const current: WorkspaceState = fs.existsSync(stateFile)
    ? JSON.parse(fs.readFileSync(stateFile, "utf8")) as WorkspaceState
    : { version: 1, name: workspace.name, updatedAt, stages: {} };
  current.updatedAt = updatedAt;
  current.stages[stage] = { stage, updatedAt, fingerprint };
  fs.writeFileSync(stateFile, `${JSON.stringify(current, null, 2)}\n`);
}

function stableObjectWithout(input: Record<string, unknown>, ignoredKeys: string[]): Record<string, unknown> {
  const ignored = new Set(ignoredKeys);
  return Object.fromEntries(Object.entries(input).filter(([key]) => !ignored.has(key)));
}

function stableJson(input: unknown): string {
  return JSON.stringify(sortStable(input));
}

function sortStable(input: unknown): unknown {
  if (Array.isArray(input)) return input.map(sortStable);
  if (!input || typeof input !== "object") return input;
  return Object.fromEntries(Object.entries(input as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, sortStable(value)]));
}
