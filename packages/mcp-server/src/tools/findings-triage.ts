import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TriageService } from "@vardionix/core";

export function registerFindingsTriage(
  server: McpServer,
  triageService: TriageService,
): void {
  server.tool(
    "findings_triage",
    "Get a batch of findings with surrounding code context for AI-assisted triage. Returns findings ready for classification as true positive, false positive, or needs investigation. Use scan_summary first to identify which categories to triage.",
    {
      category: z
        .string()
        .optional()
        .describe("Filter by vulnerability category (e.g., 'xss', 'sql-injection', 'http-methods')"),
      severity: z
        .string()
        .optional()
        .describe("Filter by severity: 'critical', 'high', 'medium', 'low', 'info'"),
      source: z
        .string()
        .optional()
        .describe("Filter by scanner source: 'semgrep', 'codeql', 'trivy'"),
      workspace: z
        .string()
        .optional()
        .describe("Filter findings to a specific workspace/project path prefix"),
      limit: z
        .number()
        .optional()
        .describe("Number of findings to return (default: 10, max: 50)"),
      offset: z
        .number()
        .optional()
        .describe("Skip first N findings for pagination"),
    },
    async (args) => {
      try {
        const batch = triageService.getTriageBatch({
          category: args.category,
          severity: args.severity as never,
          filePathPrefix: args.workspace,
          source: args.source,
          limit: args.limit,
          offset: args.offset,
        });

        const lines: string[] = [
          `## Triage Batch`,
          ``,
          batch.summary,
          ``,
          `**Showing:** ${batch.findings.length} of ${batch.total} total findings (offset: ${batch.offset})`,
          batch.hasMore ? `**More available** — increase offset to see next batch.` : `**No more findings** in this filter.`,
          ``,
          `---`,
        ];

        for (const f of batch.findings) {
          lines.push(
            ``,
            `### ${f.id} — ${f.title}`,
            `**Severity:** ${f.effectiveSeverity} | **Category:** ${f.category} | **Source:** ${f.source}`,
            `**File:** ${f.filePath}:${f.startLine}-${f.endLine}`,
            `**Rule:** ${f.ruleId}`,
            `**Confidence:** ${f.confidenceScore ?? "N/A"}`,
            ``,
            `**Message:** ${f.message}`,
            ``,
          );

          if (f.codeContext) {
            lines.push(`**Code Context:**`, `\`\`\``, f.codeContext, `\`\`\``, ``);
          } else if (f.codeSnippet) {
            lines.push(`**Code Snippet:**`, `\`\`\``, f.codeSnippet, `\`\`\``, ``);
          }

          if (f.remediationGuidance) {
            lines.push(`**Remediation:** ${f.remediationGuidance}`, ``);
          }

          lines.push(`---`);
        }

        lines.push(
          ``,
          `## Triage Instructions`,
          `For each finding, classify as:`,
          `- **True Positive** — real vulnerability, needs fix`,
          `- **False Positive** — safe code, dismiss with reason`,
          `- **Needs Investigation** — unclear, needs more context`,
          ``,
          `Use \`findings_batch_dismiss\` to dismiss false positives.`,
          `Use \`finding_fix\` to get fix context for true positives.`,
        );

        return {
          content: [
            {
              type: "text" as const,
              text: lines.join("\n"),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
