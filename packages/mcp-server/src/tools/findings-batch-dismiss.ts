import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TriageService } from "@vardionix/core";

export function registerFindingsBatchDismiss(
  server: McpServer,
  triageService: TriageService,
): void {
  server.tool(
    "findings_batch_dismiss",
    "Dismiss multiple findings at once as false positives or accepted risks. Provide finding IDs and a common reason. Use after triaging findings with findings_triage.",
    {
      findingIds: z
        .array(z.string())
        .describe("Array of finding IDs to dismiss"),
      reason: z
        .string()
        .describe("Reason for dismissal (e.g., 'false-positive: input is sanitized upstream', 'accepted-risk: internal tool only')"),
      action: z
        .enum(["dismiss", "reopen"])
        .optional()
        .describe("Action to take: 'dismiss' (default) or 'reopen' previously dismissed findings"),
    },
    async (args) => {
      try {
        if (args.findingIds.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No finding IDs provided.",
              },
            ],
            isError: true,
          };
        }

        if (args.action === "reopen") {
          const result = triageService.batchReopen(args.findingIds);
          return {
            content: [
              {
                type: "text" as const,
                text: [
                  `## Batch Reopen Result`,
                  ``,
                  `**Reopened:** ${result.reopened}`,
                  result.notFound.length > 0
                    ? `**Not found:** ${result.notFound.join(", ")}`
                    : "",
                ]
                  .filter(Boolean)
                  .join("\n"),
              },
            ],
          };
        }

        const result = triageService.batchDismiss(args.findingIds, args.reason);

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Batch Dismiss Result`,
                ``,
                `**Dismissed:** ${result.dismissed}`,
                `**Reason:** ${args.reason}`,
                result.notFound.length > 0
                  ? `**Not found:** ${result.notFound.join(", ")}`
                  : "",
              ]
                .filter(Boolean)
                .join("\n"),
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
