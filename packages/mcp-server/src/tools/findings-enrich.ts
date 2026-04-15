import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ScanOrchestrator } from "@vardionix/core";

export function registerFindingsEnrich(
  server: McpServer,
  orchestrator: ScanOrchestrator,
): void {
  server.tool(
    "findings_enrich",
    "Enrich security findings with internal policy context including severity overrides, owner teams, and remediation guidance.",
    {
      findingIds: z
        .array(z.string())
        .optional()
        .describe("List of finding IDs to enrich. If omitted, enriches all open findings."),
    },
    async (args) => {
      try {
        const enriched = orchestrator.enrichFindings(args.findingIds);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ items: enriched }, null, 2),
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
