import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface VardionixConfig {
  semgrep: {
    path: string;
    defaultRuleset: string;
    timeout: number;
  };
  policy: {
    directories: string[];
  };
  backendai: {
    endpoint: string;
    apiKey: string;
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
  policy: {
    directories: ["built-in"],
  },
  backendai: {
    endpoint: "",
    apiKey: "",
  },
  output: {
    defaultFormat: "table",
    color: true,
  },
};

export function getConfigPath(): string {
  return join(homedir(), ".vardionix", "config.yaml");
}

export function getBuiltInPoliciesDir(): string {
  // Resolve from package root
  const packageRoot = join(__dirname, "..", "..");
  const policiesDir = join(packageRoot, "policies");
  if (existsSync(policiesDir)) return policiesDir;

  // Try from monorepo root
  const monorepoRoot = join(__dirname, "..", "..", "..", "..");
  return join(monorepoRoot, "policies");
}

export function loadConfig(configPath?: string): VardionixConfig {
  const path = configPath ?? getConfigPath();

  if (!existsSync(path)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const content = readFileSync(path, "utf-8");
    const parsed = YAML.parse(content) as Partial<VardionixConfig>;

    return {
      semgrep: { ...DEFAULT_CONFIG.semgrep, ...parsed.semgrep },
      policy: { ...DEFAULT_CONFIG.policy, ...parsed.policy },
      backendai: { ...DEFAULT_CONFIG.backendai, ...parsed.backendai },
      output: { ...DEFAULT_CONFIG.output, ...parsed.output },
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
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
