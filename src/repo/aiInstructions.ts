import fs from "node:fs";
import path from "node:path";
import { redactSecrets } from "../utils/redact.js";

export interface AiInstructions {
  path?: string;
  content: string;
  chars: number;
}

const candidates = [
  "AI_INSTRUCTIONS.md",
  "AGENT.md",
  "AGENTS.md",
  ".codeguardian/AI_INSTRUCTIONS.md",
  ".codeguardian/AGENT.md"
];

export function loadAiInstructions(repoPath: string, maxChars = 20_000): AiInstructions {
  for (const name of candidates) {
    const absolute = path.join(repoPath, name);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) continue;
    const raw = fs.readFileSync(absolute, "utf8").slice(0, maxChars);
    const content = redactSecrets(raw).trim();
    return { path: name, content, chars: content.length };
  }
  return { content: "", chars: 0 };
}
