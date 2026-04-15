import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ExplainService } from "@vardionix/core";

export function registerFindingExplain(
  server: McpServer,
  explainService: ExplainService,
): void {
  server.tool(
    "finding_explain",
    "Get a structured explanation of a security finding including why it matters, what to change, and safe coding examples.",
    {
      findingId: z.string().describe("The finding ID to explain (e.g., 'F-abc123def456')"),
    },
    async (args) => {
      try {
        const explanation = explainService.explain(args.findingId);

        if (!explanation) {
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

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(explanation, null, 2),
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
