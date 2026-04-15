import { Command } from "commander";
import chalk from "chalk";
import type { ValidateService } from "@vardionix/core";
import { formatJson } from "../formatters/json.js";

export function createRemoteCommand(validateService: ValidateService): Command {
  const remote = new Command("remote").description("Manage remote validation jobs");

  remote
    .command("logs <jobId>")
    .description("Show logs for a remote validation job")
    .option("--json", "Output as JSON")
    .action(async (jobId, opts) => {
      try {
        const job = await validateService.getJob(jobId);

        if (!job) {
          console.error(`Job '${jobId}' not found.`);
          process.exitCode = 1;
          return;
        }

        if (opts.json) {
          console.log(formatJson(job));
          return;
        }

        console.log(chalk.bold(`\nJob: ${job.id}`));
        console.log(`  Status:    ${job.status}`);
        console.log(`  Template:  ${job.templateId}`);
        if (job.findingId) {
          console.log(`  Finding:   ${job.findingId}`);
        }
        console.log(`  Created:   ${job.createdAt}`);
        if (job.completedAt) {
          console.log(`  Completed: ${job.completedAt}`);
        }

        if (job.logs) {
          console.log(chalk.bold("\nLogs:"));
          console.log(chalk.gray(job.logs));
        }

        console.log();
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`,
        );
        process.exitCode = 1;
      }
    });

  remote
    .command("list")
    .description("List remote validation jobs")
    .option("--finding <findingId>", "Filter by finding ID")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const jobs = validateService.listJobs(opts.finding);

      if (opts.json) {
        console.log(formatJson(jobs));
        return;
      }

      if (jobs.length === 0) {
        console.log(chalk.yellow("No remote jobs found."));
        return;
      }

      console.log(chalk.bold("\nRemote Jobs:\n"));
      for (const j of jobs) {
        console.log(
          `  ${chalk.cyan(j.id.padEnd(16))} ${j.status.padEnd(12)} ${j.templateId} ${chalk.gray(j.createdAt)}`,
        );
      }
      console.log();
    });

  return remote;
}
