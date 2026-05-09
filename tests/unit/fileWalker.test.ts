import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { walkRepo } from "../../src/repo/fileWalker.js";

describe("file walker", () => {
  it("respects default ignores and gitignore", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-walk-"));
    fs.mkdirSync(path.join(dir, "node_modules"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".gitignore"), "ignored.txt\n");
    fs.writeFileSync(path.join(dir, "node_modules", "x.js"), "bad");
    fs.writeFileSync(path.join(dir, "ignored.txt"), "bad");
    fs.writeFileSync(path.join(dir, "src", "ok.js"), "good");
    const files = walkRepo(dir).map((file) => path.relative(dir, file).split(path.sep).join("/"));
    expect(files).toContain("src/ok.js");
    expect(files).not.toContain("node_modules/x.js");
    expect(files).not.toContain("ignored.txt");
  });
});
