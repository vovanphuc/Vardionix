import { Command } from "commander";
import chalk from "chalk";
import type { ScanOrchestrator } from "@vardionix/core";
import { formatJson } from "../formatters/json.js";

export function createPolicyCommand(orchestrator: ScanOrchestrator): Command {
  const policy = new Command("policy").description("Manage security policies");

  policy
    .command("show <policyId>")
    .description("Show details of a security policy")
    .option("--json", "Output as JSON")
    .action((policyId, opts) => {
      const policyStore = orchestrator.getPolicyStore();
      const result = policyStore.getPolicy(policyId);

      if (!result) {
        console.error(`Policy '${policyId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(result));
        return;
      }

      console.log(chalk.bold(`\nPolicy: ${result.id}`));
      console.log(`  ${chalk.gray("Title:")}       ${result.title}`);
      console.log(`  ${chalk.gray("Category:")}    ${result.category}`);
      console.log(`  ${chalk.gray("Description:")} ${result.description}`);
      if (result.severityOverride) {
        console.log(`  ${chalk.gray("Severity:")}    ${result.severityOverride}`);
      }

      console.log(chalk.bold("\n  Rule Patterns:"));
      for (const pattern of result.rulePatterns) {
        console.log(`    • ${pattern}`);
      }

      console.log(chalk.bold("\n  Remediation:"));
      console.log(`    ${result.remediationGuidance}`);

      if (result.references.length > 0) {
        console.log(chalk.bold("\n  References:"));
        for (const ref of result.references) {
          console.log(`    ${chalk.blue(ref)}`);
        }
      }

      console.log();
    });

  policy
    .command("list")
    .description("List all loaded policies")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const policyStore = orchestrator.getPolicyStore();
      const all = policyStore.getAllPolicies();

      if (opts.json) {
        console.log(formatJson(all));
        return;
      }

      if (all.length === 0) {
        console.log(chalk.yellow("No policies loaded."));
        return;
      }

      console.log(chalk.bold("\nLoaded Policies:\n"));
      for (const p of all) {
        console.log(`  ${chalk.cyan(p.id.padEnd(16))} ${p.title} ${chalk.gray(`(${p.category})`)}`);
      }
      console.log();
    });

  return policy;
}
