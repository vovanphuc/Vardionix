import chalk from "chalk";
import type { ActiveFinding, ExcludedFinding, Finding } from "@vardionix/schemas";

const SEVERITY_COLORS: Record<string, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

function colorSeverity(severity: string): string {
  const colorFn = SEVERITY_COLORS[severity] ?? chalk.white;
  return colorFn(severity.toUpperCase().padEnd(8));
}

function statusIcon(status: string): string {
  switch (status) {
    case "open":
      return chalk.red("\u25cf");
    case "dismissed":
      return chalk.gray("\u25cb");
    case "reviewed":
      return chalk.yellow("\u25cf");
    case "fixed":
      return chalk.green("\u2713");
    default:
      return "?";
  }
}

export function formatFindingsTable(findings: ActiveFinding[]): string {
  if (findings.length === 0) {
    return chalk.green("No findings found.");
  }

  const header = [
    chalk.bold("Status".padEnd(8)),
    chalk.bold("ID".padEnd(16)),
    chalk.bold("Severity".padEnd(10)),
    chalk.bold("File".padEnd(40)),
    chalk.bold("Title"),
  ].join(" ");

  const separator = chalk.gray("\u2500".repeat(100));

  const rows = findings.map((f) => {
    const effectiveSev = f.policySeverityOverride ?? f.severity;
    const fileLoc = `${truncate(f.filePath, 35)}:${f.startLine}`;
    return [
      `  ${statusIcon(f.status)}    `,
      f.id.padEnd(16),
      colorSeverity(effectiveSev),
      chalk.cyan(fileLoc.padEnd(40)),
      truncate(f.title, 40),
    ].join(" ");
  });

  return [separator, header, separator, ...rows, separator].join("\n");
}

export function formatExcludedFindingsTable(findings: ExcludedFinding[]): string {
  if (findings.length === 0) {
    return chalk.green("No excluded findings found.");
  }

  const header = [
    chalk.bold("ID".padEnd(16)),
    chalk.bold("Severity".padEnd(10)),
    chalk.bold("File".padEnd(32)),
    chalk.bold("Reason"),
  ].join(" ");

  const separator = chalk.gray("\u2500".repeat(110));

  const rows = findings.map((f) => [
    f.id.padEnd(16),
    colorSeverity(f.policySeverityOverride ?? f.severity),
    chalk.cyan(`${truncate(f.filePath, 27)}:${f.startLine}`.padEnd(32)),
    truncate(f.exclusionReason, 48),
  ].join(" "));

  return [separator, header, separator, ...rows, separator].join("\n");
}

export function formatFindingDetail(finding: Finding): string {
  const lines: string[] = [];
  const effectiveSev = finding.policySeverityOverride ?? finding.severity;

  lines.push(chalk.bold(`Finding ${finding.id}`));
  lines.push("");
  lines.push(`  ${chalk.gray("Kind:")}      ${finding.kind}`);
  lines.push(`  ${chalk.gray("Rule:")}      ${finding.ruleId}`);
  lines.push(`  ${chalk.gray("Severity:")}  ${colorSeverity(effectiveSev)}`);
  if (finding.kind === "active") {
    lines.push(`  ${chalk.gray("Status:")}    ${statusIcon(finding.status)} ${finding.status}`);
  } else {
    lines.push(`  ${chalk.gray("Excluded:")}  ${finding.excludedAt}`);
  }
  lines.push(`  ${chalk.gray("File:")}      ${chalk.cyan(finding.filePath)}:${finding.startLine}-${finding.endLine}`);
  lines.push(`  ${chalk.gray("Source:")}    ${finding.source}`);
  lines.push("");
  lines.push(chalk.bold("  Message:"));
  lines.push(`  ${finding.message}`);

  if (finding.codeSnippet) {
    lines.push("");
    lines.push(chalk.bold("  Code:"));
    lines.push(chalk.gray("  " + finding.codeSnippet.replace(/\n/g, "\n  ")));
  }

  if (finding.policyId) {
    lines.push("");
    lines.push(chalk.bold("  Policy:"));
    lines.push(`  ${chalk.gray("ID:")}     ${finding.policyId}`);
    lines.push(`  ${chalk.gray("Title:")}  ${finding.policyTitle ?? ""}`);
  }

  if (finding.remediationGuidance) {
    lines.push("");
    lines.push(chalk.bold("  Remediation:"));
    lines.push(`  ${finding.remediationGuidance}`);
  }

  if (finding.kind === "excluded") {
    lines.push("");
    lines.push(chalk.bold("  Exclusion:"));
    lines.push(`  ${finding.exclusionReason}`);
  }

  lines.push("");
  lines.push(chalk.gray(`  First seen: ${finding.firstSeenAt}`));
  lines.push(chalk.gray(`  Last seen:  ${finding.lastSeenAt}`));

  return lines.join("\n");
}

export function formatScanSummary(result: {
  scanId: string;
  totalFindings: number;
  totalExcluded: number;
  findingsBySeverity: Record<string, number>;
  excludedByReason: Record<string, number>;
  target: string;
  completedAt: string;
}): string {
  const lines: string[] = [];

  lines.push(chalk.bold(`\nScan Complete: ${result.scanId}`));
  lines.push(`  Target: ${chalk.cyan(result.target)}`);
  lines.push(`  Total findings: ${result.totalFindings === 0 ? chalk.green("0") : chalk.yellow(String(result.totalFindings))}`);

  if (result.totalFindings > 0) {
    lines.push("  By severity:");
    for (const [severity, count] of Object.entries(result.findingsBySeverity)) {
      if (count > 0) {
        lines.push(`    ${colorSeverity(severity)} ${count}`);
      }
    }
  }

  if (result.totalExcluded > 0) {
    lines.push(`  Excluded findings: ${chalk.gray(String(result.totalExcluded))}`);
    for (const [reason, count] of Object.entries(result.excludedByReason)) {
      lines.push(`    ${chalk.gray(reason)} ${count}`);
    }
  }

  return lines.join("\n");
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}
