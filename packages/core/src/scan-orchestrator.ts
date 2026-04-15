import { randomUUID } from "node:crypto";
import { execSync } from "node:child_process";
import { resolve } from "node:path";
import {
  type ScanRequest,
  type ScanResult,
  type Finding,
  ScanScope,
  Severity,
} from "@vardionix/schemas";
import { FindingsStore } from "@vardionix/store";
import {
  SemgrepRunner,
  parseSemgrepOutput,
  normalizeFindings,
  PolicyLocalStore,
  PolicyEnricher,
  filterFindings,
} from "@vardionix/adapters";
import type { VardionixConfig } from "./config.js";
import { resolvePolicyDirectories, resolveRuleset } from "./config.js";

export class ScanOrchestrator {
  private semgrepRunner: SemgrepRunner;
  private policyStore: PolicyLocalStore;
  private policyEnricher: PolicyEnricher;

  constructor(
    private config: VardionixConfig,
    private findingsStore: FindingsStore,
  ) {
    this.semgrepRunner = new SemgrepRunner({
      semgrepPath: config.semgrep.path,
      timeout: config.semgrep.timeout * 1000,
    });

    const policyDirs = resolvePolicyDirectories(config);
    this.policyStore = new PolicyLocalStore(policyDirs);
    this.policyStore.load();
    this.policyEnricher = new PolicyEnricher(this.policyStore);
  }

  async scan(request: ScanRequest): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const scanId = `S-${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 8)}-${randomUUID().slice(0, 6)}`;

    // Resolve targets based on scope
    const targets = this.resolveTargets(request);
    const target = targets.join(", ") || request.target || ".";

    // Run semgrep
    const semgrepOutput = await this.semgrepRunner.scan({
      targets,
      ruleset: resolveRuleset(request.ruleset ?? this.config.semgrep.defaultRuleset),
    });

    // Parse and normalize
    const parsed = parseSemgrepOutput(semgrepOutput);
    let findings = normalizeFindings(parsed);

    // Apply severity filter if specified
    if (request.severityFilter && request.severityFilter.length > 0) {
      findings = findings.filter((f) =>
        request.severityFilter!.includes(f.severity),
      );
    }

    // Enrich with policy data
    findings = this.policyEnricher.enrichFindings(findings);

    // Apply two-stage false-positive filtering (from claude-code-security-review)
    const filterResult = filterFindings(findings, {
      confidenceThreshold: 0.8,
    });
    findings = filterResult.kept;

    // Persist both kept and excluded findings
    this.findingsStore.upsertFindings(findings);
    this.findingsStore.upsertFindings(filterResult.excluded);

    // Compute stats
    const findingsBySeverity = this.computeSeverityStats(findings);

    const completedAt = new Date().toISOString();

    return {
      scanId,
      startedAt,
      completedAt,
      target,
      scope: request.scope,
      totalFindings: findings.length,
      findingsBySeverity,
      findingIds: findings.map((f) => f.id),
    };
  }

  enrichFindings(findingIds?: string[]): Finding[] {
    // Reload policies
    this.policyStore.load();

    let findings: Finding[];
    if (findingIds && findingIds.length > 0) {
      findings = findingIds
        .map((id) => this.findingsStore.getFinding(id))
        .filter((f): f is Finding => f !== null);
    } else {
      findings = this.findingsStore.listFindings({ status: "open" as Finding["status"] });
    }

    const enriched = this.policyEnricher.enrichFindings(findings);

    // Update store with enrichment data
    for (const finding of enriched) {
      if (finding.policyId) {
        this.findingsStore.updatePolicyEnrichment(
          finding.id,
          finding.policyId,
          finding.policyTitle ?? "",
          finding.policySeverityOverride,
          finding.remediationGuidance ?? "",
        );
      }
    }

    return enriched;
  }

  getPolicyStore(): PolicyLocalStore {
    return this.policyStore;
  }

  private resolveTargets(request: ScanRequest): string[] {
    switch (request.scope) {
      case ScanScope.FILE:
        if (!request.target) throw new Error("Target file path is required for file scope");
        return [resolve(request.target)];

      case ScanScope.DIR:
        if (!request.target) throw new Error("Target directory is required for dir scope");
        return [resolve(request.target)];

      case ScanScope.STAGED:
        return this.getStagedFiles();

      case ScanScope.WORKSPACE:
        return [this.getWorkspaceRoot()];

      default:
        throw new Error(`Unknown scan scope: ${request.scope}`);
    }
  }

  private getStagedFiles(): string[] {
    try {
      const output = execSync("git diff --cached --name-only --diff-filter=ACMR", {
        encoding: "utf-8",
        timeout: 10_000,
      }).trim();

      if (!output) return [];
      return output.split("\n").filter((f) => f.length > 0);
    } catch {
      throw new Error(
        "Failed to get staged files. Make sure you are in a git repository with staged changes.",
      );
    }
  }

  private getWorkspaceRoot(): string {
    try {
      return execSync("git rev-parse --show-toplevel", {
        encoding: "utf-8",
        timeout: 5_000,
      }).trim();
    } catch {
      return process.cwd();
    }
  }

  private computeSeverityStats(
    findings: Finding[],
  ): Record<Severity, number> {
    const stats: Record<string, number> = {};
    for (const severity of Object.values(Severity)) {
      stats[severity] = 0;
    }
    for (const f of findings) {
      const sev = f.policySeverityOverride ?? f.severity;
      stats[sev] = (stats[sev] ?? 0) + 1;
    }
    return stats as Record<Severity, number>;
  }
}
