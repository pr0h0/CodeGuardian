import type { Db } from "./database.js";
import { schemaSql } from "./schema.js";

export function runMigrations(db: Db): void {
  db.exec(schemaSql);
}
