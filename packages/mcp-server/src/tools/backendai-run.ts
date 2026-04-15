import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ValidateService } from "@vardionix/core";

export function registerBackendaiRun(
  server: McpServer,
  validateService: ValidateService,
): void {
  server.tool(
    "backendai_run_validation",
    "Submit a remote validation job to Backend.AI using an approved template. Only whitelisted job templates are allowed.",
    {
      findingId: z.string().describe("The finding ID to validate"),
      templateId: z.string().describe("The job template ID (e.g., 'go-sec-validate')"),
      repo: z.string().optional().describe("Repository name for workspace context"),
      branch: z.string().optional().describe("Branch name for workspace context"),
    },
    async (args) => {
      try {
        const workspaceMeta =
          args.repo && args.branch
            ? { repo: args.repo, branch: args.branch }
            : undefined;

        const job = await validateService.submitValidation(
          args.findingId,
          args.templateId,
          workspaceMeta,
        );

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
