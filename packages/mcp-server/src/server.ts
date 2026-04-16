import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  createAppContext,
  type VardionixAppContext,
} from "@vardionix/core";

import { registerSemgrepScan } from "./tools/semgrep-scan.js";
import { registerFindingsEnrich } from "./tools/findings-enrich.js";
import { registerFindingExplain } from "./tools/finding-explain.js";
import { registerPolicyLookup } from "./tools/policy-lookup.js";

export function createServer(
  context: VardionixAppContext = createAppContext(),
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

  return server;
}
