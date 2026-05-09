export function lineCount(content: string): number {
  if (content.length === 0) return 0;
  return content.split(/\r?\n/).length;
}

export function lineSlice(content: string, startLine: number, endLine: number): string {
  return content.split(/\r?\n/).slice(Math.max(0, startLine - 1), endLine).join("\n");
}

export function lineAtOffset(content: string, offset: number): number {
  return content.slice(0, offset).split(/\r?\n/).length;
}
