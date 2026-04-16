import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import YAML from "yaml";

export interface VardionixConfig {
  semgrep: {
    path: string;
    defaultRuleset: string;
    timeout: number;
  };
  codeql?: {
    path: string;
    querySuite: string;
    timeout: number;
    enabled: boolean;
  };
  trivy?: {
    path: string;
    timeout: number;
    enabled: boolean;
    ignoreUnfixed: boolean;
  };
  policy: {
    directories: string[];
  };
  output: {
    defaultFormat: "table" | "json" | "sarif";
    color: boolean;
  };
}

const DEFAULT_CONFIG: VardionixConfig = {
  semgrep: {
    path: "semgrep",
    defaultRuleset: "auto",
    timeout: 300,
  },
  codeql: {
    path: "codeql",
    querySuite: "security-extended",
    timeout: 600,
    enabled: false,
  },
  trivy: {
    path: "trivy",
    timeout: 120,
    enabled: true,
    ignoreUnfixed: false,
  },
  policy: {
    directories: ["built-in"],
  },
  output: {
    defaultFormat: "table",
    color: true,
  },
};

export function getConfigPath(): string {
  return join(homedir(), ".vardionix", "config.yaml");
}

/**
 * Search for a named directory by checking multiple candidate paths.
 * Works in both ESM (monorepo) and CJS (bundled extension) contexts.
 */
function findDir(name: string): string {
  const candidates = [
    // 1. Relative to cwd (monorepo development)
    join(process.cwd(), name),
    // 2. Relative to the main script (bundled extension)
    join(dirname(process.argv[1] ?? ""), name),
    // 3. Walk up from cwd
    join(process.cwd(), "..", name),
    join(process.cwd(), "..", "..", name),
    // 4. Home directory config
    join(homedir(), ".vardionix", name),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  return candidates[0]; // fallback to cwd-based
}

export function getBuiltInPoliciesDir(): string {
  return findDir("policies");
}

export function getBuiltInRulesDir(): string {
  return findDir("rules");
}

export function resolveRuleset(ruleset: string): string {
  if (ruleset === "auto") {
    // Use built-in rules if available, otherwise pass "auto" to semgrep
    const rulesDir = getBuiltInRulesDir();
    const defaultRules = join(rulesDir, "default.yaml");
    if (existsSync(defaultRules)) return defaultRules;
    return ruleset;
  }
  return ruleset;
}

export function loadConfig(configPath?: string): VardionixConfig {
  const path = configPath ?? getConfigPath();

  let config: VardionixConfig;

  if (!existsSync(path)) {
    config = { ...DEFAULT_CONFIG };
  } else {
    try {
      const content = readFileSync(path, "utf-8");
      const parsed = YAML.parse(content) as Partial<VardionixConfig>;

      config = {
        semgrep: { ...DEFAULT_CONFIG.semgrep, ...parsed.semgrep },
        codeql: parsed.codeql
          ? { ...DEFAULT_CONFIG.codeql!, ...parsed.codeql }
          : DEFAULT_CONFIG.codeql,
        trivy: parsed.trivy
          ? { ...DEFAULT_CONFIG.trivy!, ...parsed.trivy }
          : DEFAULT_CONFIG.trivy,
        policy: { ...DEFAULT_CONFIG.policy, ...parsed.policy },
        output: { ...DEFAULT_CONFIG.output, ...parsed.output },
      };
    } catch {
      config = { ...DEFAULT_CONFIG };
    }
  }

  // Allow VS Code extension (or other callers) to override semgrep path via env var
  if (process.env.VARDIONIX_SEMGREP_PATH) {
    config.semgrep.path = process.env.VARDIONIX_SEMGREP_PATH;
  }

  return config;
}

export function resolvePolicyDirectories(config: VardionixConfig): string[] {
  return config.policy.directories.map((dir) => {
    if (dir === "built-in") {
      return getBuiltInPoliciesDir();
    }
    return dir.replace("~", homedir());
  });
}

export function initConfig(): void {
  const path = getConfigPath();
  if (existsSync(path)) return;

  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const yaml = YAML.stringify(DEFAULT_CONFIG);
  writeFileSync(path, yaml, "utf-8");
}
