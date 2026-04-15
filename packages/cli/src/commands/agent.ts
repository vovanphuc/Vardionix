import { Command } from "commander";
import chalk from "chalk";
import { ScanScope } from "@vardionix/schemas";
import type { ScanOrchestrator, ExplainService, PatchService } from "@vardionix/core";
import type { FindingsStore } from "@vardionix/store";
import { formatJson } from "../formatters/json.js";

export function createAgentCommand(
  orchestrator: ScanOrchestrator,
  findingsStore: FindingsStore,
  explainService: ExplainService,
  patchService: PatchService,
): Command {
  const agent = new Command("agent").description("Agent workflow wrappers");

  // vardionix agent claude triage --scope staged
  const claude = new Command("claude").description("Claude Code agent workflows");

  claude
    .command("triage")
    .description("Triage findings using Claude-optimized workflow")
    .option("--scope <scope>", "Scan scope (file, dir, staged, workspace)", "staged")
    .option("--target <target>", "Target path (for file/dir scope)")
    .option("--json", "Output as JSON")
    .action(async (opts) => {
      try {
        // Step 1: Scan
        const result = await orchestrator.scan({
          scope: opts.scope as ScanScope,
          target: opts.target,
          ruleset: "auto",
        });

        // Step 2: Explain top findings
        const explanations = result.findingIds
          .slice(0, 10) // Top 10
          .map((id) => explainService.explain(id))
          .filter((e) => e !== null);

        const triageResult = {
          scan: result,
          explanations,
        };

        if (opts.json) {
          console.log(formatJson(triageResult));
          return;
        }

        console.log(chalk.bold(`\nTriage Report (${result.totalFindings} findings)`));
        console.log(chalk.gray(`Scan: ${result.scanId}\n`));

        for (const exp of explanations) {
          console.log(chalk.bold(`  ${exp.findingId} - ${exp.title}`));
          console.log(chalk.gray(`    Severity: ${exp.effectiveSeverity}`));
          console.log(`    ${exp.whyItMatters}`);
          console.log();
        }

        if (result.totalFindings > explanations.length) {
          console.log(
            chalk.yellow(
              `  ... and ${result.totalFindings - explanations.length} more findings. Use 'vardionix findings list' to see all.`,
            ),
          );
        }
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`,
        );
        process.exitCode = 1;
      }
    });

  agent.addCommand(claude);

  // vardionix agent codex fix F-1024
  const codex = new Command("codex").description("Codex agent workflows");

  codex
    .command("fix <findingId>")
    .description("Generate a fix for a finding using Codex-optimized workflow")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      const context = patchService.generatePatchContext(findingId);

      if (!context) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(context));
        return;
      }

      console.log(chalk.bold(`\nCodex Fix Context for ${findingId}\n`));
      console.log(context.prompt);
    });

  codex
    .command("batch-fix")
    .description("Generate fixes for multiple findings")
    .option("--severity <level>", "Filter by severity", "high")
    .option("--limit <n>", "Max findings to fix", "5")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const findings = findingsStore.listFindings({
        severity: opts.severity,
        status: "open" as never,
        limit: parseInt(opts.limit, 10),
      });

      const contexts = findings
        .map((f) => patchService.generatePatchContext(f.id))
        .filter((c) => c !== null);

      if (opts.json) {
        console.log(formatJson(contexts));
        return;
      }

      console.log(chalk.bold(`\nBatch Fix: ${contexts.length} findings\n`));
      for (const ctx of contexts) {
        console.log(chalk.bold(`--- ${ctx.findingId} ---`));
        console.log(ctx.prompt);
        console.log();
      }
    });

  agent.addCommand(codex);

  return agent;
}
