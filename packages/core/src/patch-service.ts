import type { Finding } from "@vardionix/schemas";
import type { FindingsStore } from "@vardionix/store";

export interface PatchContext {
  findingId: string;
  finding: Finding;
  prompt: string;
  contextFiles: string[];
}

export class PatchService {
  constructor(private findingsStore: FindingsStore) {}

  generatePatchContext(findingId: string): PatchContext | null {
    const finding = this.findingsStore.getFinding(findingId);
    if (!finding) return null;

    const prompt = this.buildPatchPrompt(finding);

    return {
      findingId: finding.id,
      finding,
      prompt,
      contextFiles: [finding.filePath],
    };
  }

  private buildPatchPrompt(finding: Finding): string {
    const lines = [
      `## Security Finding Fix Request`,
      ``,
      `**Finding ID:** ${finding.id}`,
      `**Rule:** ${finding.ruleId}`,
      `**Severity:** ${finding.policySeverityOverride ?? finding.severity}`,
      `**File:** ${finding.filePath}:${finding.startLine}-${finding.endLine}`,
      ``,
      `### Issue`,
      finding.message,
      ``,
    ];

    if (finding.codeSnippet) {
      lines.push(`### Current Code`, `\`\`\``, finding.codeSnippet, `\`\`\``, ``);
    }

    if (finding.remediationGuidance) {
      lines.push(`### Remediation Guidance`, finding.remediationGuidance, ``);
    }

    if (finding.policyId) {
      lines.push(`### Policy`, `Policy: ${finding.policyId} - ${finding.policyTitle ?? ""}`, ``);
    }

    lines.push(
      `### Instructions`,
      `1. Fix the security finding described above.`,
      `2. Ensure the fix does not break existing functionality.`,
      `3. Follow the remediation guidance if provided.`,
      `4. Add appropriate error handling and input validation.`,
      `5. Keep changes minimal and focused on the security issue.`,
    );

    return lines.join("\n");
  }
}
