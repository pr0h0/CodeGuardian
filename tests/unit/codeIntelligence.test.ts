import { describe, expect, it } from "vitest";
import { analyzeCode } from "../../src/repo/codeIntelligence.js";

describe("code intelligence", () => {
  it("uses parser-backed JavaScript and TypeScript analysis for imports, symbols, and routes", () => {
    const content = [
      "import express from 'express';",
      "import { thing } from './thing';",
      "const app = express();",
      "const router = express.Router();",
      "export async function handler(req, res) { res.send(req.params.id); }",
      "export const helper = (value: string) => value.trim();",
      "class LocalOnly {}",
      "app.get('/users/:id', handler);",
      "router.post('/items', (req, res) => res.json({ ok: true }));"
    ].join("\n");

    const analysis = analyzeCode("src/routes.ts", content);

    expect(analysis.imports).toEqual(expect.arrayContaining(["express", "./thing"]));
    expect(analysis.symbols).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "handler", kind: "function", startLine: 5, exported: true }),
      expect.objectContaining({ name: "helper", kind: "function", startLine: 6, exported: true }),
      expect.objectContaining({ name: "LocalOnly", kind: "class", startLine: 7, exported: false })
    ]));
    expect(analysis.routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ method: "GET", routePath: "/users/:id", startLine: 8, frameworkGuess: "express" }),
      expect.objectContaining({ method: "POST", routePath: "/items", startLine: 9, frameworkGuess: "express" })
    ]));
  });
});
