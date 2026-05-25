export type FileRole =
  | "server-runtime"
  | "client"
  | "test"
  | "fixture"
  | "docs"
  | "ci"
  | "generated"
  | "dependency"
  | "unknown";

const dependencyFilePattern = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock|composer\.lock)$/i;
const generatedPathPattern = /(^|\/)(node_modules|vendor|dist|build|coverage|out|target|\.next|generated|__generated__)(\/|$)|\.min\.(js|css)$/i;
const testPathPattern = /(^|\/)(test|tests|__tests__|spec|specs|cypress|e2e)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/i;
const ciPathPattern = /(^|\/)(\.github\/workflows|\.circleci|\.gitlab-ci|azure-pipelines|buildkite|\.drone)(\/|$)|(^|\/)(Jenkinsfile|Dockerfile)$/i;
const docsPathPattern = /(^|\/)(docs?|documentation)(\/|$)|(^|\/)(README|CHANGELOG|CONTRIBUTING|LICENSE)(\.[a-z0-9]+)?$|\.(md|mdx|rst|adoc|txt)$/i;
const fixturePathPattern = /(^|\/)(fixtures?|samples?|examples?|mocks?|mock-data|seed|seeds|demo|demos|snippets?|testdata|data\/static|codefixes)(\/|$)/i;
const serverPathPattern = /(^|\/)(routes?|controllers?|handlers?|middleware|api|server|backend|app\/api|pages\/api|workers?|jobs?|commands?|cli|bin|auth|policies?|services?)(\/|$)|(^|\/)(server|app|main|index|worker|job|cli)\.[cm]?[jt]sx?$/i;
const clientPathPattern = /(^|\/)(frontend|client|web|ui|assets|public|components?|pages|views?|screens?|stores?|hooks?|styles?)(\/|$)|\.(vue|svelte|css|scss)$/i;

export function classifyFileRole(pathName: string, language = ""): FileRole {
  const normalized = normalizeRolePath(pathName);
  const languageName = language.toLowerCase();
  if (!normalized) return "unknown";
  if (dependencyFilePattern.test(normalized)) return "dependency";
  if (generatedPathPattern.test(normalized)) return "generated";
  if (testPathPattern.test(normalized)) return "test";
  if (ciPathPattern.test(normalized)) return "ci";
  if (docsPathPattern.test(normalized) || ["markdown", "text"].includes(languageName)) return "docs";
  if (fixturePathPattern.test(normalized)) return "fixture";
  if (/^(frontend|client|web|ui)\//i.test(normalized) && !/(^|\/)(app\/api|pages\/api)(\/|$)/i.test(normalized)) return "client";
  if (serverPathPattern.test(normalized)) return "server-runtime";
  if (clientPathPattern.test(normalized)) return "client";
  return "unknown";
}

export function fileRoleScore(role: FileRole): number {
  switch (role) {
    case "server-runtime":
      return 18;
    case "unknown":
      return 0;
    case "client":
      return -6;
    case "ci":
      return -32;
    case "fixture":
      return -18;
    case "test":
      return -38;
    case "docs":
      return -42;
    case "generated":
    case "dependency":
      return -65;
  }
}

export function isReusableOrGeneratedRole(role: FileRole): boolean {
  return role === "test" || role === "fixture" || role === "docs" || role === "generated" || role === "dependency";
}

function normalizeRolePath(pathName: string): string {
  return pathName.replaceAll("\\", "/").replace(/^\.\//, "");
}
