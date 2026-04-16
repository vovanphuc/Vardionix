import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TriageService } from "@vardionix/core";

export function registerFindingFix(
  server: McpServer,
  triageService: TriageService,
): void {
  server.tool(
    "finding_fix",
    "Get extended code context and fix hints for a specific finding. Returns the vulnerable code with surrounding context (±20 lines), category-specific fix suggestions, and remediation guidance. Use this to generate a targeted code fix.",
    {
      findingId: z.string().describe("The finding ID to get fix context for (e.g., 'F-abc123def456')"),
    },
    async (args) => {
      try {
        const fixCtx = triageService.getFixContext(args.findingId);

        if (!fixCtx) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Finding '${args.findingId}' not found.`,
              },
            ],
            isError: true,
          };
        }

        const f = fixCtx.finding;
        const lines: string[] = [
          `## Fix Context: ${f.id}`,
          ``,
          `**Title:** ${f.title}`,
          `**Severity:** ${f.policySeverityOverride ?? f.severity}`,
          `**Category:** ${f.category ?? "uncategorized"}`,
          `**Rule:** ${f.ruleId}`,
          `**File:** ${f.filePath}:${f.startLine}-${f.endLine}`,
          ``,
          `### Issue`,
          f.message,
          ``,
          `### Vulnerable Code (±5 lines)`,
          `\`\`\``,
          fixCtx.codeContext,
          `\`\`\``,
          ``,
          `### Surrounding Code (±20 lines)`,
          `\`\`\``,
          fixCtx.surroundingCode,
          `\`\`\``,
          ``,
          `### Fix Hints`,
          ...fixCtx.fixHints.map((h, i) => `${i + 1}. ${h}`),
          ``,
          `### Instructions`,
          `1. Fix the security issue described above.`,
          `2. Keep changes minimal — fix only the vulnerability.`,
          `3. Do not refactor surrounding code.`,
          `4. Ensure the fix does not break existing functionality.`,
          `5. After fixing, re-scan the file to verify the finding is resolved.`,
        ];

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
