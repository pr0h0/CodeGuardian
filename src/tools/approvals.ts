import crypto from "node:crypto";
import type { Db } from "../db/database.js";

export function createApproval(db: Db, input: { scanId?: string; actionType: string; commandPreview: string; risk: string; reason: string; target?: string; metadata?: unknown }): string {
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO approvals (id,scan_id,action_type,command_preview,risk,reason,target,status,created_at,metadata_json)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id, input.scanId ?? null, input.actionType, input.commandPreview, input.risk, input.reason, input.target ?? null, "pending", new Date().toISOString(), JSON.stringify(input.metadata ?? {}));
  return id;
}

export function resolveApproval(db: Db, id: string, status: "approved" | "rejected"): boolean {
  const result = db.prepare("UPDATE approvals SET status = ?, resolved_at = ? WHERE id = ? AND status = 'pending'").run(status, new Date().toISOString(), id);
  return result.changes > 0;
}

export function findApproved(db: Db, actionType: string, target: string): boolean {
  const row = db.prepare("SELECT id FROM approvals WHERE action_type = ? AND target = ? AND status = 'approved'").get(actionType, target);
  return Boolean(row);
}
