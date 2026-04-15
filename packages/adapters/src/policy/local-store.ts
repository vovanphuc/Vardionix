import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import { type Policy, Severity } from "@vardionix/schemas";
import type { PolicyFile } from "./types.js";

function toSeverity(raw: string | undefined): Severity | undefined {
  if (!raw) return undefined;
  const map: Record<string, Severity> = {
    critical: Severity.CRITICAL,
    high: Severity.HIGH,
    medium: Severity.MEDIUM,
    low: Severity.LOW,
    info: Severity.INFO,
  };
  return map[raw.toLowerCase()];
}

export class PolicyLocalStore {
  private policies: Map<string, Policy> = new Map();

  constructor(private directories: string[]) {}

  load(): void {
    this.policies.clear();

    for (const dir of this.directories) {
      if (!existsSync(dir)) continue;

      const files = readdirSync(dir).filter(
        (f) => f.endsWith(".yaml") || f.endsWith(".yml") || f.endsWith(".json"),
      );

      for (const file of files) {
        const content = readFileSync(join(dir, file), "utf-8");
        let parsed: PolicyFile;

        if (file.endsWith(".json")) {
          parsed = JSON.parse(content) as PolicyFile;
        } else {
          parsed = YAML.parse(content) as PolicyFile;
        }

        if (parsed.policies) {
          for (const entry of parsed.policies) {
            this.policies.set(entry.id, {
              id: entry.id,
              title: entry.title,
              description: entry.description,
              category: entry.category,
              severityOverride: toSeverity(entry.severity_override),
              rulePatterns: entry.rule_patterns,
              remediationGuidance: entry.remediation_guidance,
              references: entry.references ?? [],
            });
          }
        }
      }
    }
  }

  getPolicy(id: string): Policy | null {
    return this.policies.get(id) ?? null;
  }

  getAllPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  findPoliciesForRule(ruleId: string): Policy[] {
    return this.getAllPolicies().filter((policy) =>
      policy.rulePatterns.some((pattern) => ruleMatchesPattern(ruleId, pattern)),
    );
  }
}

function ruleMatchesPattern(ruleId: string, pattern: string): boolean {
  // Support simple glob patterns: "javascript.lang.security.*" matches "javascript.lang.security.audit.xss"
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return ruleId.startsWith(prefix);
  }
  // Exact match
  return ruleId === pattern;
}
