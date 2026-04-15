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

// Findings filter (inspired by claude-code-security-review)
export {
  filterFindings,
  applyHardExclusions,
  applyConfidenceThreshold,
  type FilterResult,
} from "./filter/index.js";

// Backend.AI adapter
export {
  BackendAIClient,
  ALLOWED_TEMPLATES,
  getTemplate,
  isTemplateAllowed,
  type JobTemplate,
  type SubmitJobRequest,
  type JobResult,
} from "./backendai/index.js";
