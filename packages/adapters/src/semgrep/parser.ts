import type { SemgrepJsonOutput, SemgrepResult } from "./types.js";

export interface ParsedSemgrepFinding {
  checkId: string;
  filePath: string;
  startLine: number;
  endLine: number;
  startCol: number;
  endCol: number;
  message: string;
  severity: string;
  codeSnippet?: string;
  metadata?: Record<string, unknown>;
  fix?: string;
}

export function parseSemgrepOutput(
  output: SemgrepJsonOutput,
): ParsedSemgrepFinding[] {
  return output.results
    .filter((result) => !result.extra.is_ignored)
    .map(parseSingleResult);
}

function parseSingleResult(result: SemgrepResult): ParsedSemgrepFinding {
  return {
    checkId: result.check_id,
    filePath: result.path,
    startLine: result.start.line,
    endLine: result.end.line,
    startCol: result.start.col,
    endCol: result.end.col,
    message: result.extra.message,
    severity: normalizeSeverityString(result.extra.severity),
    codeSnippet: result.extra.lines,
    metadata: result.extra.metadata,
    fix: result.extra.fix,
  };
}

function normalizeSeverityString(severity: string): string {
  const s = severity.toLowerCase();
  switch (s) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "info":
    case "information":
      return "info";
    default:
      return s;
  }
}
