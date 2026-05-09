export type PromptKind = "security-triage" | "dynamic-test" | "poc" | "code-quality" | "remediation" | "false-positive";

export function buildTaskPrompt(kind: PromptKind, input: unknown): string {
  return [
    `Role: senior security engineer.`,
    `Objective: ${kind}.`,
    `Scope: use only supplied inputs.`,
    `Inputs: ${JSON.stringify(input)}`,
    "Constraints: evidence required, no invented files, no unrestricted shell, no external target unless allowlisted.",
    "Required output schema: strict JSON where requested.",
    "Safety rules: redact secrets, do not execute commands.",
    "What not to do: do not claim certainty without evidence."
  ].join("\n");
}
