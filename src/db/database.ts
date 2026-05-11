import Database from "better-sqlite3";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";
import { schemaSql } from "./schema.js";

export type Db = Database.Database;

export function openDatabase(dbPath: string): Db {
  ensureDir(path.dirname(path.resolve(dbPath)));
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.exec(schemaSql);
  runCompatMigrations(db);
  return db;
}

function runCompatMigrations(db: Db): void {
  addColumn(db, "findings", "fingerprint", "TEXT");
  addColumn(db, "findings", "baseline_status", "TEXT");
  addColumn(db, "findings", "exploitability_score", "INTEGER");
  addColumn(db, "scanner_results", "fingerprint", "TEXT");
}

function addColumn(db: Db, table: string, column: string, definition: string): void {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!columns.some((item) => item.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
