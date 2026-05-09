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
  return db;
}
