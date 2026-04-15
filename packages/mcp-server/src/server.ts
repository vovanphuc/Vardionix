import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  loadConfig,
  ScanOrchestrator,
  ExplainService,
  PatchService,
  ValidateService,
} from "@vardionix/core";
import { getDatabase, FindingsStore } from "@vardionix/store";

import { registerSemgrepScan } from "./tools/semgrep-scan.js";
import { registerFindingsEnrich } from "./tools/findings-enrich.js";
import { registerFindingExplain } from "./tools/finding-explain.js";
import { registerBackendaiRun } from "./tools/backendai-run.js";
import { registerBackendaiJob } from "./tools/backendai-job.js";
import { registerPolicyLookup } from "./tools/policy-lookup.js";

export function createServer(): McpServer {
  const config = loadConfig();
  const db = getDatabase();
  const findingsStore = new FindingsStore(db);

  const orchestrator = new ScanOrchestrator(config, findingsStore);
  const explainService = new ExplainService(findingsStore);
  const _patchService = new PatchService(findingsStore);
  const validateService = new ValidateService(
    findingsStore,
    db,
    config.backendai.endpoint || undefined,
    config.backendai.apiKey || undefined,
  );

  const server = new McpServer({
    name: "vardionix",
    version: "0.1.0",
  });

  // Register all tools
  registerSemgrepScan(server, orchestrator);
  registerFindingsEnrich(server, orchestrator);
  registerFindingExplain(server, explainService);
  registerBackendaiRun(server, validateService);
  registerBackendaiJob(server, validateService);
  registerPolicyLookup(server, orchestrator);

  return server;
}
