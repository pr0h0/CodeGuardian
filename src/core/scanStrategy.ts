import type { ProjectConfig } from "../config/projectConfig.js";

export interface ScanStrategyMetadata {
  focusPaths: string[];
  avoidPaths: string[];
  vulnerabilityClasses: string[];
  rulesOfEngagement: string;
  reportFilters: Record<string, string>;
}

export function buildScanStrategyInstructions(config: Partial<ProjectConfig>): string {
  const lines: string[] = [];
  if (config.vulnerabilityClasses?.length) {
    lines.push(`Vulnerability classes in scope: ${config.vulnerabilityClasses.join(", ")}.`);
    lines.push("Treat out-of-scope vulnerability classes as lower priority unless the supplied evidence shows a clear chained impact into an in-scope class.");
  }
  const rules = config.rulesOfEngagement?.trim();
  if (rules) lines.push(`Rules of engagement: ${rules}`);
  const guidance = config.reportFilters?.guidance?.trim();
  if (guidance) lines.push(`Report guidance: ${guidance}`);
  if (config.reportFilters?.minSeverity) lines.push(`Report minimum severity: ${config.reportFilters.minSeverity}.`);
  if (config.reportFilters?.minConfidence) lines.push(`Report minimum confidence: ${config.reportFilters.minConfidence}.`);
  return lines.length ? ["Project scan strategy:", ...lines.map((line) => `- ${line}`)].join("\n") : "";
}

export function scanStrategyMetadata(config: Partial<ProjectConfig>): ScanStrategyMetadata {
  return {
    focusPaths: [...(config.focusPaths ?? [])],
    avoidPaths: [...(config.avoidPaths ?? [])],
    vulnerabilityClasses: [...(config.vulnerabilityClasses ?? [])],
    rulesOfEngagement: config.rulesOfEngagement?.trim() ?? "",
    reportFilters: cleanReportFilters(config.reportFilters)
  };
}

export function combineAiInstructions(repositoryInstructions: string, strategyInstructions: string): string {
  return [repositoryInstructions.trim(), strategyInstructions.trim()].filter(Boolean).join("\n\n");
}

function cleanReportFilters(filters: ProjectConfig["reportFilters"] | undefined): Record<string, string> {
  const output: Record<string, string> = {};
  if (filters?.minSeverity) output.minSeverity = filters.minSeverity;
  if (filters?.minConfidence) output.minConfidence = filters.minConfidence;
  if (filters?.guidance?.trim()) output.guidance = filters.guidance.trim();
  return output;
}
