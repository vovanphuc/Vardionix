import * as path from "path";
import * as vscode from "vscode";
import {
  type Finding,
  type FindingsGroupingMode,
  getEffectiveSeverity,
  SEVERITY_ORDER,
  severityRank,
} from "./diagnostics";

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const SEVERITY_ICONS: Record<string, vscode.ThemeIcon> = {
  critical: new vscode.ThemeIcon("error", new vscode.ThemeColor("testing.iconFailed")),
  high: new vscode.ThemeIcon("warning", new vscode.ThemeColor("testing.iconFailed")),
  medium: new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground")),
  low: new vscode.ThemeIcon("info", new vscode.ThemeColor("testing.iconPassed")),
  info: new vscode.ThemeIcon("info", new vscode.ThemeColor("descriptionForeground")),
};

type TreeNode = PendingGroupItem | FileGroupItem | SeverityGroupItem | FindingItem;

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly onDidChangeEmitter = new vscode.EventEmitter<TreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.onDidChangeEmitter.event;

  private findings: Finding[] = [];
  private grouping: FindingsGroupingMode = "file";

  setFindings(findings: Finding[]): void {
    this.findings = findings;
    this.refresh();
  }

  setGrouping(grouping: FindingsGroupingMode): void {
    this.grouping = grouping;
    this.refresh();
  }

  getGrouping(): FindingsGroupingMode {
    return this.grouping;
  }

  getFindings(): Finding[] {
    return this.findings;
  }

  getSeverityCounts(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const finding of this.findings) {
      if (finding.status !== "open" || finding.pendingVerification) {
        continue;
      }

      const severity = getEffectiveSeverity(finding);
      counts[severity] = (counts[severity] ?? 0) + 1;
    }
    return counts;
  }

  refresh(): void {
    this.onDidChangeEmitter.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      return this.getRootChildren();
    }

    if (element instanceof PendingGroupItem) {
      return this.getPendingFindings().map((finding) => new FindingItem(finding));
    }

    if (element instanceof FileGroupItem) {
      const findings = this.getNonPendingFindings().filter((finding) => finding.filePath === element.filePath);
      return this.groupSeverityGroups(findings, element.filePath);
    }

    if (element instanceof SeverityGroupItem) {
      return element.findings.map((finding) => new FindingItem(finding));
    }

    return [];
  }

  private getRootChildren(): TreeNode[] {
    const nodes: TreeNode[] = [];
    const pendingFindings = this.getPendingFindings();

    if (pendingFindings.length > 0) {
      nodes.push(new PendingGroupItem(pendingFindings.length));
    }

    if (this.grouping === "severity") {
      return [...nodes, ...this.groupSeverityGroups(this.getNonPendingFindings())];
    }

    return [...nodes, ...this.groupFileGroups(this.getNonPendingFindings())];
  }

  private getPendingFindings(): Finding[] {
    return this.findings.filter((finding) => finding.pendingVerification);
  }

  private getNonPendingFindings(): Finding[] {
    return this.findings.filter((finding) => !finding.pendingVerification);
  }

  private groupFileGroups(findings: Finding[]): FileGroupItem[] {
    const byFile = new Map<string, Finding[]>();
    for (const finding of findings) {
      if (!byFile.has(finding.filePath)) {
        byFile.set(finding.filePath, []);
      }
      byFile.get(finding.filePath)!.push(finding);
    }

    return Array.from(byFile.entries())
      .sort(([fileA], [fileB]) => relativePath(fileA).localeCompare(relativePath(fileB)))
      .map(([filePath, fileFindings]) => new FileGroupItem(filePath, fileFindings));
  }

  private groupSeverityGroups(findings: Finding[], filePath?: string): SeverityGroupItem[] {
    const bySeverity = new Map<string, Finding[]>();
    for (const finding of findings) {
      const severity = getEffectiveSeverity(finding);
      if (!bySeverity.has(severity)) {
        bySeverity.set(severity, []);
      }
      bySeverity.get(severity)!.push(finding);
    }

    return [...SEVERITY_ORDER]
      .reverse()
      .filter((severity) => (bySeverity.get(severity) ?? []).length > 0)
      .map((severity) =>
        new SeverityGroupItem(
          severity,
          sortFindings(bySeverity.get(severity)!, filePath),
          filePath,
        )
      );
  }
}

class PendingGroupItem extends vscode.TreeItem {
  constructor(count: number) {
    super("Pending Verification", vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${count}`;
    this.iconPath = new vscode.ThemeIcon("sync~spin", new vscode.ThemeColor("list.warningForeground"));
    this.contextValue = "pendingGroup";
    this.tooltip = "Findings touched by edits and waiting for a confirming rescan.";
  }
}

class FileGroupItem extends vscode.TreeItem {
  constructor(
    public readonly filePath: string,
    findings: Finding[],
  ) {
    super(relativePath(filePath), vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${findings.length}`;
    this.tooltip = filePath;
    this.iconPath = new vscode.ThemeIcon("file-code");
    this.contextValue = "fileGroup";
  }
}

class SeverityGroupItem extends vscode.TreeItem {
  constructor(
    public readonly severity: string,
    public readonly findings: Finding[],
    filePath?: string,
  ) {
    super(SEVERITY_LABELS[severity] ?? severity, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${findings.length}`;
    this.tooltip = filePath
      ? `${SEVERITY_LABELS[severity] ?? severity} findings in ${relativePath(filePath)}`
      : `${SEVERITY_LABELS[severity] ?? severity} findings`;
    this.iconPath = SEVERITY_ICONS[severity] ?? SEVERITY_ICONS.info;
    this.contextValue = "severityGroup";
  }
}

export class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(
      finding.pendingVerification ? `${finding.title} (Pending verification)` : finding.title,
      vscode.TreeItemCollapsibleState.None,
    );

    this.description = finding.pendingVerification
      ? `${relativePath(finding.filePath)}:${finding.startLine} · waiting for rescan`
      : `${relativePath(finding.filePath)}:${finding.startLine}`;
    this.tooltip = new vscode.MarkdownString(buildFindingTooltip(finding));
    this.contextValue = finding.pendingVerification ? "finding pendingFinding" : "finding";
    this.iconPath = finding.pendingVerification
      ? new vscode.ThemeIcon("sync~spin", new vscode.ThemeColor("list.warningForeground"))
      : undefined;

    this.command = {
      command: "vscode.open",
      title: "Go to Finding",
      arguments: [
        vscode.Uri.file(finding.filePath),
        {
          selection: new vscode.Range(
            Math.max(0, finding.startLine - 1),
            0,
            Math.max(0, finding.endLine - 1),
            Number.MAX_SAFE_INTEGER,
          ),
        },
      ],
    };
  }
}

function buildFindingTooltip(finding: Finding): string {
  const severity = getEffectiveSeverity(finding);
  const lines = [
    `**${finding.title}**`,
    "",
    finding.pendingVerification
      ? `$(sync~spin) **PENDING VERIFICATION** \u00b7 \`${finding.id}\``
      : `$(${severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "info"}) **${severity.toUpperCase()}** \u00b7 \`${finding.ruleId}\``,
    "",
    finding.message,
  ];

  if (finding.pendingVerification) {
    lines.push("", "This finding was touched by a recent edit and is waiting for a confirming rescan.");
  }

  if (finding.remediationGuidance) {
    lines.push("", "---", "", `**Remediation:** ${finding.remediationGuidance}`);
  }

  if (finding.status !== "open") {
    lines.push("", `**Status:** ${finding.status}`);
  }

  return lines.join("\n");
}

function sortFindings(findings: Finding[], parentFilePath?: string): Finding[] {
  return [...findings].sort((left, right) => {
    if (!parentFilePath && left.filePath !== right.filePath) {
      return relativePath(left.filePath).localeCompare(relativePath(right.filePath));
    }

    const severityDelta = severityRank(getEffectiveSeverity(right))
      - severityRank(getEffectiveSeverity(left));
    if (severityDelta !== 0) {
      return severityDelta;
    }

    if (left.startLine !== right.startLine) {
      return left.startLine - right.startLine;
    }

    return left.title.localeCompare(right.title);
  });
}

function relativePath(filePath: string): string {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    return filePath;
  }

  for (const folder of workspaceFolders) {
    if (filePath.startsWith(folder.uri.fsPath)) {
      return filePath.slice(folder.uri.fsPath.length + 1);
    }
  }

  return path.basename(filePath);
}
