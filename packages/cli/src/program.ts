import { Command } from "commander";
import {
  loadConfig,
  ScanOrchestrator,
  ExplainService,
  PatchService,
  ValidateService,
} from "@vardionix/core";
import { getDatabase, FindingsStore } from "@vardionix/store";

import { createScanCommand } from "./commands/scan.js";
import { createFindingsCommand, createFindingCommand } from "./commands/findings.js";
import { createExplainCommand } from "./commands/explain.js";
import { createPatchCommand } from "./commands/patch.js";
import { createValidateCommand } from "./commands/validate.js";
import { createPolicyCommand } from "./commands/policy.js";
import { createRemoteCommand } from "./commands/remote.js";
import { createAgentCommand } from "./commands/agent.js";

export function createProgram(): Command {
  const config = loadConfig();
  const db = getDatabase();
  const findingsStore = new FindingsStore(db);

  const orchestrator = new ScanOrchestrator(config, findingsStore);
  const explainService = new ExplainService(findingsStore);
  const patchService = new PatchService(findingsStore);
  const validateService = new ValidateService(
    findingsStore,
    db,
    config.backendai.endpoint || undefined,
    config.backendai.apiKey || undefined,
  );

  const program = new Command();

  program
    .name("vardionix")
    .description("Vardionix - Unified DevSecOps CLI")
    .version("0.1.0");

  // Register commands
  program.addCommand(createScanCommand(orchestrator, findingsStore));
  program.addCommand(createFindingsCommand(findingsStore));
  program.addCommand(createFindingCommand(findingsStore));
  program.addCommand(createExplainCommand(explainService));
  program.addCommand(createPatchCommand(patchService));
  program.addCommand(createValidateCommand(validateService));
  program.addCommand(createPolicyCommand(orchestrator));
  program.addCommand(createRemoteCommand(validateService));
  program.addCommand(createAgentCommand(orchestrator, findingsStore, explainService, patchService));

  return program;
}
