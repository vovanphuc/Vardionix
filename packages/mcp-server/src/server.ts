import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  createAppContext,
  type VardionixAppContext,
} from "@vardionix/core";

import { registerSemgrepScan } from "./tools/semgrep-scan.js";
import { registerFindingsEnrich } from "./tools/findings-enrich.js";
import { registerFindingExplain } from "./tools/finding-explain.js";
import { registerPolicyLookup } from "./tools/policy-lookup.js";
import { registerScanSummary } from "./tools/scan-summary.js";
import { registerFindingsTriage } from "./tools/findings-triage.js";
import { registerFindingFix } from "./tools/finding-fix.js";
import { registerFindingsBatchDismiss } from "./tools/findings-batch-dismiss.js";

export function createServer(
  context: VardionixAppContext,
): McpServer {

  const server = new McpServer({
    name: "vardionix",
    version: "0.1.0",
  });

  // Register all tools
  registerSemgrepScan(server, context.scanService);
  registerFindingsEnrich(server, context.scanService);
  registerFindingExplain(server, context.explainService);
  registerPolicyLookup(server, context.scanService);

  // AI triage tools
  registerScanSummary(server, context.triageService);
  registerFindingsTriage(server, context.triageService);
  registerFindingFix(server, context.triageService);
  registerFindingsBatchDismiss(server, context.triageService);

  return server;
}

export async function createDefaultServer(): Promise<McpServer> {
  const context = await createAppContext();
  return createServer(context);
}
