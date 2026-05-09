import path from "node:path";

const byExt: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".go": "go", ".php": "php", ".rb": "ruby",
  ".java": "java", ".kt": "kotlin", ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
  ".rs": "rust", ".swift": "swift", ".scala": "scala", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
  ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".xml": "xml", ".html": "html", ".css": "css"
};

export function detectLanguage(filePath: string, firstLine = ""): string {
  const ext = path.extname(filePath).toLowerCase();
  if (byExt[ext]) return byExt[ext];
  if (firstLine.startsWith("#!")) {
    if (firstLine.includes("python")) return "python";
    if (firstLine.includes("node")) return "javascript";
    if (firstLine.includes("ruby")) return "ruby";
    if (firstLine.includes("bash") || firstLine.includes("sh")) return "shell";
  }
  return "unknown";
}
