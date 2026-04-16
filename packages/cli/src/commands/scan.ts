import { Command } from "commander";
import { ScanScope, type Severity } from "@vardionix/schemas";
import type { ScanService } from "@vardionix/core";
import type { FindingsStore } from "@vardionix/store";
import { formatScanSummary, formatFindingsTable } from "../formatters/table.js";
import { formatJson } from "../formatters/json.js";
import { formatSarif } from "../formatters/sarif.js";

export function createScanCommand(
  scanService: ScanService,
  findingsStore: FindingsStore,
): Command {
  const scan = new Command("scan").description("Scan code for security findings");

  scan
    .command("file <path>")
    .description("Scan a single file")
    .option("--ruleset <ruleset>", "Semgrep ruleset", "auto")
    .option("--json", "Output as JSON")
    .option("--sarif", "Output as SARIF")
    .option("--severity <levels>", "Filter by severity (comma-separated)")
    .option("--fail-on <level>", "Exit with code 1 if findings at or above level")
    .action(async (path, opts) => {
      await runScan(scanService, findingsStore, ScanScope.FILE, path, opts);
    });

  scan
    .command("dir <path>")
    .description("Scan a directory")
    .option("--ruleset <ruleset>", "Semgrep ruleset", "auto")
    .option("--json", "Output as JSON")
    .option("--sarif", "Output as SARIF")
    .option("--severity <levels>", "Filter by severity (comma-separated)")
    .option("--fail-on <level>", "Exit with code 1 if findings at or above level")
    .action(async (path, opts) => {
      await runScan(scanService, findingsStore, ScanScope.DIR, path, opts);
    });

  scan
    .command("staged")
    .description("Scan git staged files")
    .option("--ruleset <ruleset>", "Semgrep ruleset", "auto")
    .option("--json", "Output as JSON")
    .option("--sarif", "Output as SARIF")
    .option("--severity <levels>", "Filter by severity (comma-separated)")
    .option("--fail-on <level>", "Exit with code 1 if findings at or above level")
    .action(async (opts) => {
      await runScan(scanService, findingsStore, ScanScope.STAGED, undefined, opts);
    });

  scan
    .command("workspace")
    .description("Scan entire workspace")
    .option("--ruleset <ruleset>", "Semgrep ruleset", "auto")
    .option("--json", "Output as JSON")
    .option("--sarif", "Output as SARIF")
    .option("--severity <levels>", "Filter by severity (comma-separated)")
    .option("--fail-on <level>", "Exit with code 1 if findings at or above level")
    .option("--max-files <n>", "Maximum files to scan", "300")
    .action(async (opts) => {
      await runScan(scanService, findingsStore, ScanScope.WORKSPACE, undefined, opts);
    });

  return scan;
}

interface ScanOpts {
  ruleset: string;
  json?: boolean;
  sarif?: boolean;
  severity?: string;
  failOn?: string;
}

async function runScan(
  scanService: ScanService,
  findingsStore: FindingsStore,
  scope: ScanScope,
  target: string | undefined,
  opts: ScanOpts,
): Promise<void> {
  try {
    const severityFilter = opts.severity
      ? (opts.severity.split(",").map((s) => s.trim()) as Severity[])
      : undefined;

    const result = await scanService.scan({
      scope,
      target,
      ruleset: opts.ruleset,
      severityFilter,
    });

    if (opts.sarif) {
      const findings = result.findingIds
        .map((id) => findingsStore.getFinding(id))
        .filter((f) => f !== null);
      console.log(formatSarif(findings));
    } else if (opts.json) {
      console.log(formatJson(result));
    } else {
      console.log(formatScanSummary(result));

      if (result.totalFindings > 0) {
        const findings = result.findingIds
          .map((id) => findingsStore.getFinding(id))
          .filter((f) => f !== null);
        console.log(formatFindingsTable(findings));
      }
    }

    // Check fail-on threshold
    if (opts.failOn) {
      const failLevel = opts.failOn.toLowerCase();
      const severityOrder = ["info", "low", "medium", "high", "critical"];
      const failIdx = severityOrder.indexOf(failLevel);

      if (failIdx >= 0) {
        for (const [sev, count] of Object.entries(result.findingsBySeverity)) {
          if (count > 0 && severityOrder.indexOf(sev) >= failIdx) {
            process.exitCode = 1;
            return;
          }
        }
      }
    }
  } catch (error) {
    console.error(
      `Error: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 1;
  }
}
