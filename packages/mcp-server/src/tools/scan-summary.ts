import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TriageService } from "@vardionix/core";

export function registerScanSummary(
  server: McpServer,
  triageService: TriageService,
): void {
  server.tool(
    "scan_summary",
    "Get a comprehensive summary of scan results including severity breakdown, top vulnerability categories, scanner source distribution, and file hotspots. Use this after scanning to understand the landscape before triaging individual findings.",
    {
      workspace: z
        .string()
        .optional()
        .describe("Filter findings to a specific workspace/project path prefix"),
    },
    async (args) => {
      try {
        const summary = triageService.getScanSummary(args.workspace);

        // Build a human-readable summary alongside the data
        const lines: string[] = [
          `## Scan Summary`,
          ``,
          `**Total open findings:** ${summary.total}`,
          ``,
          `### By Severity`,
          ...Object.entries(summary.bySeverity)
            .filter(([, count]) => count > 0)
            .sort(([, a], [, b]) => b - a)
            .map(([sev, count]) => `- ${sev}: ${count}`),
          ``,
          `### By Scanner`,
          ...Object.entries(summary.bySource)
            .sort(([, a], [, b]) => b - a)
            .map(([src, count]) => `- ${src}: ${count}`),
          ``,
          `### Top Categories`,
          ...summary.byCategory.slice(0, 15).map(
            (c) =>
              `- **${c.category}** (${c.count}): ${Object.entries(c.severities)
                .map(([s, n]) => `${s}=${n}`)
                .join(", ")}`,
          ),
          ``,
          `### Top Files (by finding count)`,
          ...summary.topFiles.slice(0, 10).map(
            (f) => `- ${f.filePath} — ${f.count} findings (highest: ${f.highestSeverity})`,
          ),
        ];

        return {
          content: [
            {
              type: "text" as const,
              text: lines.join("\n"),
            },
            {
              type: "text" as const,
              text: JSON.stringify(summary, null, 2),
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
