import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ScanService } from "@vardionix/core";

export function registerPolicyLookup(
  server: McpServer,
  scanService: ScanService,
): void {
  server.tool(
    "policy_lookup",
    "Look up an internal security policy by its ID. Returns the policy details including checklist, references, and remediation guidance.",
    {
      policyId: z.string().describe("The policy ID to look up (e.g., 'SEC-GO-014')"),
    },
    async (args) => {
      try {
        const policyStore = scanService.getPolicyStore();
        const policy = policyStore.getPolicy(args.policyId);

        if (!policy) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Policy '${args.policyId}' not found.`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(policy, null, 2),
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
