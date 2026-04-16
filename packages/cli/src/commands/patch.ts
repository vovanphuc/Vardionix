import { Command } from "commander";
import chalk from "chalk";
import type { PatchService } from "@vardionix/core";
import { formatJson } from "../formatters/json.js";

export function createPatchCommand(patchService: PatchService): Command {
  return new Command("patch")
    .description("Generate a patch prompt for a security finding")
    .argument("<findingId>", "Finding ID to patch")
    .option("--agent <agent>", "Agent to use (codex, claude)", "codex")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      let context;
      try {
        context = patchService.generatePatchContext(findingId);
      } catch (error) {
        console.error(error instanceof Error ? error.message : String(error));
        process.exitCode = 1;
        return;
      }

      if (!context) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(context));
        return;
      }

      console.log(chalk.bold(`\nPatch Context for ${findingId}`));
      console.log(chalk.gray(`Agent: ${opts.agent}`));
      console.log(chalk.gray(`Files: ${context.contextFiles.join(", ")}`));
      console.log(chalk.bold("\nGenerated prompt:"));
      console.log(context.prompt);
      console.log();
    });
}
