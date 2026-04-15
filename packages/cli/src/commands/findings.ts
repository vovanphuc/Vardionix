import { Command } from "commander";
import { FindingStatus, type Severity } from "@vardionix/schemas";
import type { FindingsStore } from "@vardionix/store";
import { formatFindingsTable, formatFindingDetail } from "../formatters/table.js";
import { formatJson } from "../formatters/json.js";

export function createFindingsCommand(findingsStore: FindingsStore): Command {
  const findings = new Command("findings").description("Manage security findings");

  findings
    .command("list")
    .description("List all findings")
    .option("--open-only", "Show only open findings")
    .option("--severity <level>", "Filter by severity")
    .option("--json", "Output as JSON")
    .option("--limit <n>", "Limit results", "100")
    .action((opts) => {
      const filters: Record<string, unknown> = {};
      if (opts.openOnly) filters.status = FindingStatus.OPEN;
      if (opts.severity) filters.severity = opts.severity as Severity;
      if (opts.limit) filters.limit = parseInt(opts.limit, 10);

      const results = findingsStore.listFindings(filters as never);

      if (opts.json) {
        console.log(formatJson(results));
      } else {
        console.log(formatFindingsTable(results));
      }
    });

  findings
    .command("show <findingId>")
    .alias("finding show")
    .description("Show details of a finding")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      const finding = findingsStore.getFinding(findingId);
      if (!finding) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(finding));
      } else {
        console.log(formatFindingDetail(finding));
      }
    });

  findings
    .command("dismiss <findingId>")
    .description("Dismiss a finding")
    .option("--reason <reason>", "Reason for dismissal")
    .option("--local", "Dismiss locally only")
    .action((findingId, opts) => {
      const success = findingsStore.updateStatus(
        findingId,
        FindingStatus.DISMISSED,
        opts.reason,
      );

      if (!success) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} dismissed.`);
    });

  findings
    .command("review <findingId>")
    .description("Mark a finding as reviewed")
    .action((findingId) => {
      const success = findingsStore.updateStatus(findingId, FindingStatus.REVIEWED);

      if (!success) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} marked as reviewed.`);
    });

  return findings;
}

export function createFindingCommand(findingsStore: FindingsStore): Command {
  const finding = new Command("finding").description("Show a single finding");

  finding
    .command("show <findingId>")
    .description("Show details of a finding")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      const result = findingsStore.getFinding(findingId);
      if (!result) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      if (opts.json) {
        console.log(formatJson(result));
      } else {
        console.log(formatFindingDetail(result));
      }
    });

  finding
    .command("dismiss <findingId>")
    .description("Dismiss a finding")
    .option("--reason <reason>", "Reason for dismissal")
    .option("--local", "Dismiss locally only")
    .action((findingId, opts) => {
      const success = findingsStore.updateStatus(
        findingId,
        FindingStatus.DISMISSED,
        opts.reason,
      );

      if (!success) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} dismissed.`);
    });

  finding
    .command("review <findingId>")
    .description("Mark a finding as reviewed")
    .action((findingId) => {
      const success = findingsStore.updateStatus(findingId, FindingStatus.REVIEWED);

      if (!success) {
        console.error(`Finding '${findingId}' not found.`);
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} marked as reviewed.`);
    });

  return finding;
}
