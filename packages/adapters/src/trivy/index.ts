export {
  TrivyRunner,
  TrivyNotInstalledError,
  TrivyScanError,
  type TrivyRunnerOptions,
} from "./runner.js";

export {
  parseTrivyOutput,
  type ParsedTrivyVulnerability,
} from "./parser.js";

export {
  normalizeTrivyFindings,
} from "./normalizer.js";

export type {
  TrivyJsonOutput,
  TrivyResult,
  TrivyVulnerability,
} from "./types.js";
