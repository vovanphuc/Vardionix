import { Command } from "commander";
import {
  createAppContext,
  type VardionixAppContext,
} from "@vardionix/core";

import { createScanCommand } from "./commands/scan.js";
import { createFindingsCommand, createFindingCommand } from "./commands/findings.js";
import { createExplainCommand } from "./commands/explain.js";
import { createPatchCommand } from "./commands/patch.js";
import { createPolicyCommand } from "./commands/policy.js";
import { createAgentCommand } from "./commands/agent.js";

export function createProgram(
  context: VardionixAppContext = createAppContext(),
): Command {

  const program = new Command();

  program
    .name("vardionix")
    .description("Vardionix - Unified DevSecOps CLI")
    .version("0.1.0");

  // Register commands
  program.addCommand(createScanCommand(context.scanService, context.findingsStore));
  program.addCommand(
    createFindingsCommand(context.findingsStore, context.excludedFindingsStore),
  );
  program.addCommand(
    createFindingCommand(context.findingsStore, context.excludedFindingsStore),
  );
  program.addCommand(createExplainCommand(context.explainService));
  program.addCommand(createPatchCommand(context.patchService));
  program.addCommand(createPolicyCommand(context.scanService));
  program.addCommand(
    createAgentCommand(
      context.scanService,
      context.findingsStore,
      context.explainService,
      context.patchService,
    ),
  );

  return program;
}
