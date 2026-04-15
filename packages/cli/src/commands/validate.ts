import { Command } from "commander";
import chalk from "chalk";
import type { ValidateService } from "@vardionix/core";
import { formatJson } from "../formatters/json.js";

export function createValidateCommand(validateService: ValidateService): Command {
  return new Command("validate")
    .description("Validate a finding fix remotely")
    .argument("<findingId>", "Finding ID to validate")
    .option("--remote", "Run validation on Backend.AI")
    .option("--template <template>", "Job template ID", "generic-unit-test")
    .option("--repo <repo>", "Repository name")
    .option("--branch <branch>", "Branch name")
    .option("--json", "Output as JSON")
    .action(async (findingId, opts) => {
      try {
        const workspaceMeta =
          opts.repo && opts.branch
            ? { repo: opts.repo, branch: opts.branch }
            : undefined;

        const job = await validateService.submitValidation(
          findingId,
          opts.template,
          workspaceMeta,
        );

        if (opts.json) {
          console.log(formatJson(job));
          return;
        }

        console.log(chalk.bold(`\nValidation Job Submitted`));
        console.log(`  Job ID:    ${chalk.cyan(job.id)}`);
        console.log(`  Template:  ${job.templateId}`);
        console.log(`  Status:    ${job.status}`);
        console.log(`  Finding:   ${findingId}`);
        if (job.logs) {
          console.log(chalk.gray(`\n  ${job.logs}`));
        }
        console.log();
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`,
        );
        process.exitCode = 1;
      }
    });
}
