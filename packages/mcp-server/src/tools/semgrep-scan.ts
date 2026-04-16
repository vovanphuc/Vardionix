import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ScanScope, type Severity } from "@vardionix/schemas";
import type { ScanService } from "@vardionix/core";

export function registerSemgrepScan(
  server: McpServer,
  scanService: ScanService,
): void {
  server.tool(
    "semgrep_scan",
    "Scan files or directories for security findings using Semgrep. Supports scanning individual files, directories, staged git changes, or the entire workspace.",
    {
      scope: z.enum(["file", "dir", "staged", "workspace"]).describe(
        "Scan scope: 'file' for a single file, 'dir' for a directory, 'staged' for git staged changes, 'workspace' for the entire workspace",
      ),
      target: z
        .string()
        .optional()
        .describe("File or directory path (required for 'file' and 'dir' scopes)"),
      ruleset: z
        .string()
        .optional()
        .describe("Semgrep ruleset to use (default: 'auto')"),
      severityFilter: z
        .string()
        .optional()
        .describe("Comma-separated severity filter (e.g., 'high,critical')"),
    },
    async (args) => {
      try {
        const severityFilter = args.severityFilter
          ? (args.severityFilter.split(",").map((s) => s.trim()) as Severity[])
          : undefined;

        const result = await scanService.scan({
          scope: args.scope as ScanScope,
          target: args.target,
          ruleset: args.ruleset ?? "auto",
          severityFilter: severityFilter as never,
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(result, null, 2),
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
