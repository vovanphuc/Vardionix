import { Command } from "commander";
import { FindingStatus, type Finding, type Severity } from "@vardionix/schemas";
import type { ExcludedFindingsStore, FindingsStore } from "@vardionix/store";
import {
  formatExcludedFindingsTable,
  formatFindingsTable,
  formatFindingDetail,
} from "../formatters/table.js";
import { formatJson } from "../formatters/json.js";

function findAnyFinding(
  findingsStore: FindingsStore,
  excludedFindingsStore: ExcludedFindingsStore,
  findingId: string,
): Finding | null {
  return findingsStore.getFinding(findingId) ?? excludedFindingsStore.getFinding(findingId);
}

export function createFindingsCommand(
  findingsStore: FindingsStore,
  excludedFindingsStore: ExcludedFindingsStore,
): Command {
  const findings = new Command("findings").description("Manage security findings");

  findings
    .command("list")
    .description("List active findings or excluded findings")
    .option("--open-only", "Show only open active findings")
    .option("--excluded", "Show excluded findings instead of active findings")
    .option("--severity <level>", "Filter by severity")
    .option("--workspace <path>", "Only show findings within this directory")
    .option("--json", "Output as JSON")
    .option("--limit <n>", "Limit results", "100")
    .action((opts) => {
      if (opts.openOnly && opts.excluded) {
        console.error("Cannot combine --open-only with --excluded.");
        process.exitCode = 1;
        return;
      }

      const filters: Record<string, unknown> = {};
      if (opts.severity) filters.severity = opts.severity as Severity;
      if (opts.limit) filters.limit = parseInt(opts.limit, 10);
      if (opts.workspace) filters.filePathPrefix = opts.workspace;

      if (opts.excluded) {
        const results = excludedFindingsStore.listFindings(filters as never);
        if (opts.json) {
          console.log(formatJson(results));
        } else {
          console.log(formatExcludedFindingsTable(results));
        }
        return;
      }

      if (opts.openOnly) filters.status = FindingStatus.OPEN;
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
      const finding = findAnyFinding(findingsStore, excludedFindingsStore, findingId);
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
    .description("Dismiss an active finding")
    .option("--reason <reason>", "Reason for dismissal")
    .option("--local", "Dismiss locally only")
    .action((findingId, opts) => {
      const success = findingsStore.updateStatus(
        findingId,
        FindingStatus.DISMISSED,
        opts.reason,
      );

      if (!success) {
        if (excludedFindingsStore.getFinding(findingId)) {
          console.error(`Finding '${findingId}' is excluded and cannot be dismissed.`);
        } else {
          console.error(`Finding '${findingId}' not found.`);
        }
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} dismissed.`);
    });

  findings
    .command("review <findingId>")
    .description("Mark an active finding as reviewed")
    .action((findingId) => {
      const success = findingsStore.updateStatus(findingId, FindingStatus.REVIEWED);

      if (!success) {
        if (excludedFindingsStore.getFinding(findingId)) {
          console.error(`Finding '${findingId}' is excluded and cannot be reviewed.`);
        } else {
          console.error(`Finding '${findingId}' not found.`);
        }
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} marked as reviewed.`);
    });

  return findings;
}

export function createFindingCommand(
  findingsStore: FindingsStore,
  excludedFindingsStore: ExcludedFindingsStore,
): Command {
  const finding = new Command("finding").description("Show a single finding");

  finding
    .command("show <findingId>")
    .description("Show details of a finding")
    .option("--json", "Output as JSON")
    .action((findingId, opts) => {
      const result = findAnyFinding(findingsStore, excludedFindingsStore, findingId);
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
    .description("Dismiss an active finding")
    .option("--reason <reason>", "Reason for dismissal")
    .option("--local", "Dismiss locally only")
    .action((findingId, opts) => {
      const success = findingsStore.updateStatus(
        findingId,
        FindingStatus.DISMISSED,
        opts.reason,
      );

      if (!success) {
        if (excludedFindingsStore.getFinding(findingId)) {
          console.error(`Finding '${findingId}' is excluded and cannot be dismissed.`);
        } else {
          console.error(`Finding '${findingId}' not found.`);
        }
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} dismissed.`);
    });

  finding
    .command("review <findingId>")
    .description("Mark an active finding as reviewed")
    .action((findingId) => {
      const success = findingsStore.updateStatus(findingId, FindingStatus.REVIEWED);

      if (!success) {
        if (excludedFindingsStore.getFinding(findingId)) {
          console.error(`Finding '${findingId}' is excluded and cannot be reviewed.`);
        } else {
          console.error(`Finding '${findingId}' not found.`);
        }
        process.exitCode = 1;
        return;
      }

      console.log(`Finding ${findingId} marked as reviewed.`);
    });

  return finding;
}
