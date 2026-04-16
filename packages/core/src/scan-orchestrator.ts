import { randomUUID } from "node:crypto";
import { execSync } from "node:child_process";
import { resolve } from "node:path";
import {
  type ScanRequest,
  type ScanSummary,
  type ActiveFinding,
  ScanScope,
  Severity,
} from "@vardionix/schemas";
import { ExcludedFindingsStore, FindingsStore } from "@vardionix/store";
import {
  SemgrepRunner,
  parseSemgrepOutput,
  normalizeFindings,
  PolicyLocalStore,
  PolicyEnricher,
  filterFindings,
  CodeQLRunner,
  parseCodeQLSarif,
  normalizeCodeQLFindings,
  TrivyRunner,
  parseTrivyOutput,
  normalizeTrivyFindings,
} from "@vardionix/adapters";
import type { VardionixConfig } from "./config.js";
import { resolveRuleset } from "./config.js";

class TargetResolver {
  resolveTargets(request: ScanRequest): string[] {
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
        stdio: "pipe",
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
        stdio: "pipe",
      }).trim();
    } catch {
      return process.cwd();
    }
  }
}

class SemgrepScanService {
  private readonly semgrepRunner: SemgrepRunner;

  constructor(config: VardionixConfig) {
    this.semgrepRunner = new SemgrepRunner({
      semgrepPath: config.semgrep.path,
      timeout: config.semgrep.timeout * 1000,
    });
  }

  async scan(request: ScanRequest, targets: string[], defaultRuleset: string): Promise<ActiveFinding[]> {
    const semgrepOutput = await this.semgrepRunner.scan({
      targets,
      ruleset: resolveRuleset(request.ruleset ?? defaultRuleset),
    });

    const parsed = parseSemgrepOutput(semgrepOutput);
    let findings = normalizeFindings(parsed);

    if (request.severityFilter && request.severityFilter.length > 0) {
      findings = findings.filter((f) => request.severityFilter!.includes(f.severity));
    }

    return findings;
  }
}

class CodeQLScanService {
  private readonly codeqlRunner: CodeQLRunner;

  constructor(config: VardionixConfig) {
    const codeqlConfig = config.codeql!;
    this.codeqlRunner = new CodeQLRunner({
      codeqlPath: codeqlConfig.path,
      timeout: codeqlConfig.timeout * 1000,
      querySuite: codeqlConfig.querySuite,
    });
  }

  isAvailable(): boolean {
    return this.codeqlRunner.checkInstalled();
  }

  async scan(sourceRoot: string, language: string): Promise<ActiveFinding[]> {
    const sarif = await this.codeqlRunner.scan({ sourceRoot, language });
    const parsed = parseCodeQLSarif(sarif);
    return normalizeCodeQLFindings(parsed);
  }
}

class TrivyScanService {
  private readonly trivyRunner: TrivyRunner;

  constructor(config: VardionixConfig) {
    this.trivyRunner = new TrivyRunner({
      trivyPath: config.trivy?.path ?? "trivy",
      timeout: (config.trivy?.timeout ?? 120) * 1000,
      ignoreUnfixed: config.trivy?.ignoreUnfixed ?? false,
    });
  }

  isAvailable(): boolean {
    return this.trivyRunner.checkInstalled();
  }

  async scan(target: string): Promise<ActiveFinding[]> {
    const output = await this.trivyRunner.scan(target);
    const parsed = parseTrivyOutput(output);
    return normalizeTrivyFindings(parsed);
  }
}

class FindingEnrichmentService {
  constructor(private readonly policyEnricher: PolicyEnricher) {}

  enrich(findings: ActiveFinding[]): ActiveFinding[] {
    return this.policyEnricher.enrichFindings(findings);
  }
}

class FindingFilterService {
  filter(findings: ActiveFinding[]) {
    return filterFindings(findings, {
      confidenceThreshold: 0.8,
    });
  }
}

export class ScanService {
  private readonly targetResolver = new TargetResolver();
  private readonly semgrepScanService: SemgrepScanService;
  private readonly codeqlScanService: CodeQLScanService | null;
  private readonly trivyScanService: TrivyScanService | null;
  private readonly enrichmentService: FindingEnrichmentService;
  private readonly filterService = new FindingFilterService();

  constructor(
    private config: VardionixConfig,
    private findingsStore: FindingsStore,
    private excludedFindingsStore: ExcludedFindingsStore,
    private policyStore: PolicyLocalStore,
    policyEnricher: PolicyEnricher,
  ) {
    this.semgrepScanService = new SemgrepScanService(config);
    this.codeqlScanService = config.codeql?.enabled
      ? new CodeQLScanService(config)
      : null;
    this.trivyScanService = config.trivy?.enabled !== false
      ? new TrivyScanService(config)
      : null;
    this.enrichmentService = new FindingEnrichmentService(policyEnricher);
  }

  async scan(request: ScanRequest): Promise<ScanSummary> {
    const startedAt = new Date().toISOString();
    const scanId = `S-${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 8)}-${randomUUID().slice(0, 6)}`;

    const targets = this.targetResolver.resolveTargets(request);
    const target = targets.join(", ") || request.target || ".";

    // Layer 1: Semgrep (fast pattern matching)
    const semgrepFindings = await this.semgrepScanService.scan(
      request,
      targets,
      this.config.semgrep.defaultRuleset,
    );

    // Layer 2: CodeQL (deep semantic analysis) — optional
    let codeqlFindings: ActiveFinding[] = [];
    if (
      this.codeqlScanService?.isAvailable() &&
      (request.scope === ScanScope.DIR || request.scope === ScanScope.WORKSPACE)
    ) {
      const sourceRoot = targets[0];
      const language = CodeQLRunner.detectLanguage(sourceRoot);
      if (language) {
        try {
          codeqlFindings = await this.codeqlScanService.scan(sourceRoot, language);
        } catch {
          // CodeQL failure is non-fatal — Semgrep results are still valid
        }
      }
    }

    // Layer 3: Trivy SCA (dependency vulnerability scanning) — optional
    let trivyFindings: ActiveFinding[] = [];
    if (
      this.trivyScanService?.isAvailable() &&
      (request.scope === ScanScope.DIR || request.scope === ScanScope.WORKSPACE)
    ) {
      const sourceRoot = targets[0];
      try {
        trivyFindings = await this.trivyScanService.scan(sourceRoot);
      } catch {
        // Trivy failure is non-fatal
      }
    }

    // Merge and deduplicate: prefer higher-confidence finding per location
    const normalized = this.deduplicateFindings([
      ...semgrepFindings,
      ...codeqlFindings,
      ...trivyFindings,
    ]);

    const enriched = this.enrichmentService.enrich(normalized);
    const filterResult = this.filterService.filter(enriched);

    this.findingsStore.upsertFindings(filterResult.kept);
    this.excludedFindingsStore.upsertFindings(filterResult.excluded);
    this.findingsStore.deleteFindings(filterResult.excluded.map((f) => f.id));
    this.excludedFindingsStore.deleteFindings(filterResult.kept.map((f) => f.id));

    const findingsBySeverity = this.computeSeverityStats(filterResult.kept);

    const completedAt = new Date().toISOString();

    return {
      scanId,
      startedAt,
      completedAt,
      target,
      scope: request.scope,
      totalFindings: filterResult.kept.length,
      totalExcluded: filterResult.excluded.length,
      findingsBySeverity,
      excludedByReason: filterResult.stats.byExclusionReason,
      findingIds: filterResult.kept.map((f) => f.id),
      excludedFindingIds: filterResult.excluded.map((f) => f.id),
    };
  }

  enrichFindings(findingIds?: string[]): ActiveFinding[] {
    this.policyStore.load();

    let findings: ActiveFinding[];
    if (findingIds && findingIds.length > 0) {
      findings = findingIds
        .map((id) => this.findingsStore.getFinding(id))
        .filter((f): f is ActiveFinding => f !== null);
    } else {
      findings = this.findingsStore.listFindings({ status: "open" as ActiveFinding["status"] });
    }

    const enriched = this.enrichmentService.enrich(findings);

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

  /**
   * Deduplicate findings from multiple scanners.
   * If both Semgrep and CodeQL report the same location, keep the one
   * with higher confidence.
   */
  private deduplicateFindings(findings: ActiveFinding[]): ActiveFinding[] {
    const byLocation = new Map<string, ActiveFinding>();

    for (const f of findings) {
      const key = `${f.filePath}:${f.startLine}:${f.category}`;
      const existing = byLocation.get(key);
      if (!existing || (f.confidenceScore ?? 0) > (existing.confidenceScore ?? 0)) {
        byLocation.set(key, f);
      }
    }

    return Array.from(byLocation.values());
  }

  private computeSeverityStats(
    findings: ActiveFinding[],
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
