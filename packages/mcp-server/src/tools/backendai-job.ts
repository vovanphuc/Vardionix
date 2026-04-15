import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ValidateService } from "@vardionix/core";

export function registerBackendaiJob(
  server: McpServer,
  validateService: ValidateService,
): void {
  server.tool(
    "backendai_get_job",
    "Get the status, logs, and results of a Backend.AI validation job.",
    {
      jobId: z.string().describe("The job ID to check (e.g., 'JOB-abc12345')"),
    },
    async (args) => {
      try {
        const job = await validateService.getJob(args.jobId);

        if (!job) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Job '${args.jobId}' not found.`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(job, null, 2),
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
