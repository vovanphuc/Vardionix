import { Command } from "commander";
import chalk from "chalk";
import type { ExplainService } from "@vardionix/core";
import { formatJson } from "../formatters/json.js";

export function createExplainCommand(explainService: ExplainService): Command {
  return new Command("explain")
    .description("Explain a security finding")
    .argument("<findingId>", "Finding ID to explain")
    .option("--agent <agent>", "Agent format (claude, codex)", "claude")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      const explanation = explainService.explain(findingId);

      if (!explanation) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(explanation));
        return;
      }

      // Formatted output
      console.log(chalk.bold(`\nExplanation: ${explanation.title}`));
      console.log(chalk.gray(`Finding: ${explanation.findingId}`));
      console.log(
        chalk.gray(
          `Severity: ${explanation.severity}${explanation.effectiveSeverity !== explanation.severity ? ` → ${explanation.effectiveSeverity} (policy override)` : ""}`,
        ),
      );

      console.log(chalk.bold("\nWhy it matters:"));
      console.log(`  ${explanation.whyItMatters}`);

      console.log(chalk.bold("\nWhat to change:"));
      for (const item of explanation.whatToChange) {
        console.log(`  • ${item}`);
      }

      console.log(chalk.bold("\nSafe pattern:"));
      console.log(`  ${explanation.safeExample}`);

      if (explanation.policyContext) {
        console.log(chalk.bold("\nPolicy context:"));
        console.log(`  Policy: ${explanation.policyContext.policyId} - ${explanation.policyContext.policyTitle}`);
        console.log(`  Guidance: ${explanation.policyContext.remediationGuidance}`);
      }

      if (explanation.codeContext) {
        console.log(chalk.bold("\nCode context:"));
        console.log(chalk.gray(`  ${explanation.codeContext.filePath}:${explanation.codeContext.startLine}-${explanation.codeContext.endLine}`));
        console.log(chalk.gray(`  ${explanation.codeContext.snippet}`));
      }

      console.log();
    });
}
