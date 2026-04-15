/**
 * Types matching Semgrep's JSON output format.
 * See: https://semgrep.dev/docs/cli-reference
 */

export interface SemgrepJsonOutput {
  version: string;
  results: SemgrepResult[];
  errors: SemgrepError[];
  paths?: {
    scanned: string[];
    skipped?: SemgrepSkippedPath[];
  };
}

export interface SemgrepResult {
  check_id: string;
  path: string;
  start: SemgrepPosition;
  end: SemgrepPosition;
  extra: SemgrepExtra;
}

export interface SemgrepPosition {
  line: number;
  col: number;
  offset: number;
}

export interface SemgrepExtra {
  message: string;
  severity: string;
  metadata?: Record<string, unknown>;
  lines?: string;
  fix?: string;
  fix_regex?: unknown;
  is_ignored?: boolean;
  fingerprint?: string;
}

export interface SemgrepError {
  code: number;
  level: string;
  type: string;
  message: string;
  path?: string;
  long_msg?: string;
}

export interface SemgrepSkippedPath {
  path: string;
  reason: string;
}
