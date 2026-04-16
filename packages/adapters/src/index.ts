// Semgrep adapter
export {
  SemgrepRunner,
  SemgrepNotInstalledError,
  SemgrepScanError,
  parseSemgrepOutput,
  normalizeFindings,
  generateFindingId,
  type SemgrepRunnerOptions,
  type SemgrepJsonOutput,
  type ParsedSemgrepFinding,
} from "./semgrep/index.js";

// Policy adapter
export {
  PolicyLocalStore,
  PolicyEnricher,
  type EnrichedFinding,
} from "./policy/index.js";

// CodeQL adapter
export {
  CodeQLRunner,
  CodeQLNotInstalledError,
  CodeQLScanError,
  parseCodeQLSarif,
  normalizeCodeQLFindings,
  type CodeQLRunnerOptions,
  type ParsedCodeQLFinding,
  type SarifLog,
} from "./codeql/index.js";

// Trivy adapter (SCA)
export {
  TrivyRunner,
  TrivyNotInstalledError,
  TrivyScanError,
  parseTrivyOutput,
  normalizeTrivyFindings,
  type TrivyRunnerOptions,
  type ParsedTrivyVulnerability,
  type TrivyJsonOutput,
} from "./trivy/index.js";

// Findings filter (inspired by claude-code-security-review)
export {
  filterFindings,
  applyHardExclusions,
  applyConfidenceThreshold,
  type FilterResult,
} from "./filter/index.js";
