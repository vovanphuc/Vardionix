import type { ActiveFinding } from "@vardionix/schemas";
import type { ExcludedFindingsStore, FindingsStore } from "@vardionix/store";

export interface FindingExplanation {
  findingId: string;
  title: string;
  severity: string;
  effectiveSeverity: string;
  whyItMatters: string;
  whatToChange: string[];
  safeExample: string;
  policyContext?: {
    policyId: string;
    policyTitle: string;
    remediationGuidance: string;
  };
  codeContext?: {
    filePath: string;
    startLine: number;
    endLine: number;
    snippet: string;
  };
}

export class ExplainService {
  constructor(
    private findingsStore: FindingsStore,
    private excludedFindingsStore: ExcludedFindingsStore,
  ) {}

  explain(findingId: string): FindingExplanation | null {
    const finding = this.findingsStore.getFinding(findingId);
    if (!finding) {
      const excluded = this.excludedFindingsStore.getFinding(findingId);
      if (excluded) {
        throw new Error(
          `Finding '${findingId}' is excluded and cannot be explained: ${excluded.exclusionReason}`,
        );
      }
      return null;
    }

    return this.buildExplanation(finding);
  }

  private buildExplanation(finding: ActiveFinding): FindingExplanation {
    const effectiveSeverity =
      finding.policySeverityOverride ?? finding.severity;

    const explanation: FindingExplanation = {
      findingId: finding.id,
      title: finding.title,
      severity: finding.severity,
      effectiveSeverity,
      whyItMatters: this.generateWhyItMatters(finding),
      whatToChange: this.generateWhatToChange(finding),
      safeExample: this.generateSafeExample(finding),
    };

    if (finding.policyId) {
      explanation.policyContext = {
        policyId: finding.policyId,
        policyTitle: finding.policyTitle ?? "",
        remediationGuidance: finding.remediationGuidance ?? "",
      };
    }

    if (finding.codeSnippet) {
      explanation.codeContext = {
        filePath: finding.filePath,
        startLine: finding.startLine,
        endLine: finding.endLine,
        snippet: finding.codeSnippet,
      };
    }

    return explanation;
  }

  private generateWhyItMatters(finding: ActiveFinding): string {
    if (finding.remediationGuidance) {
      return finding.message + " " + finding.remediationGuidance;
    }
    return finding.message;
  }

  private generateWhatToChange(finding: ActiveFinding): string[] {
    const changes: string[] = [];

    if (finding.remediationGuidance) {
      // Split guidance into actionable items
      const lines = finding.remediationGuidance
        .split(/[.;\n]/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      changes.push(...lines);
    }

    if (changes.length === 0) {
      changes.push(
        `Review the code at ${finding.filePath}:${finding.startLine}-${finding.endLine}`,
      );
      changes.push(
        `Address the finding: ${finding.message}`,
      );
    }

    return changes;
  }

  private generateSafeExample(finding: ActiveFinding): string {
    // For MVP, provide a generic safe coding guidance based on the rule pattern
    const ruleSegments = finding.ruleId.split(".");
    const lastSegment = ruleSegments[ruleSegments.length - 1];

    const safePatterns: Record<string, string> = {
      xss: "Use context-aware output encoding. Sanitize user input before rendering in HTML/JS contexts.",
      "sql-injection":
        "Use parameterized queries or prepared statements instead of string concatenation.",
      "command-injection":
        "Use allowlists for command arguments. Avoid passing user input directly to shell commands.",
      "path-traversal":
        "Validate and canonicalize file paths. Use allowlists for permitted directories.",
      ssrf: "Validate and allowlist destination URLs. Block internal/private IP ranges.",
      "insecure-deserialization":
        "Use safe deserialization methods. Validate and restrict deserialized types.",
    };

    return (
      safePatterns[lastSegment] ??
      "Use explicit guard clauses and input validation. Follow the principle of least privilege."
    );
  }
}
