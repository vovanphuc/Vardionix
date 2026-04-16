import * as vscode from "vscode";
import type { Finding } from "./diagnostics";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_ICONS: Record<string, vscode.ThemeIcon> = {
  critical: new vscode.ThemeIcon("error", new vscode.ThemeColor("testing.iconFailed")),
  high: new vscode.ThemeIcon("warning", new vscode.ThemeColor("testing.iconFailed")),
  medium: new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground")),
  low: new vscode.ThemeIcon("info", new vscode.ThemeColor("testing.iconPassed")),
  info: new vscode.ThemeIcon("info", new vscode.ThemeColor("descriptionForeground")),
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

type TreeNode = SeverityGroupItem | FindingItem;

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];
  private groupedFindings = new Map<string, Finding[]>();

  setFindings(findings: Finding[]): void {
    this.findings = findings.filter((f) => f.status === "open");
    this.rebuildGroups();
    this._onDidChangeTreeData.fire();
  }

  getFindings(): Finding[] {
    return this.findings;
  }

  /** Summary counts for status bar */
  getSeverityCounts(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of this.findings) {
      const sev = (f.policySeverityOverride ?? f.severity) as string;
      counts[sev] = (counts[sev] ?? 0) + 1;
    }
    return counts;
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      // Root level: severity group headers
      const groups: SeverityGroupItem[] = [];
      for (const sev of SEVERITY_ORDER) {
        const findings = this.groupedFindings.get(sev);
        if (findings && findings.length > 0) {
          groups.push(new SeverityGroupItem(sev, findings.length));
        }
      }
      return groups;
    }

    if (element instanceof SeverityGroupItem) {
      const findings = this.groupedFindings.get(element.severity) ?? [];
      return findings.map((f) => new FindingItem(f));
    }

    return [];
  }

  private rebuildGroups(): void {
    this.groupedFindings.clear();
    for (const f of this.findings) {
      const sev = (f.policySeverityOverride ?? f.severity) as string;
      if (!this.groupedFindings.has(sev)) {
        this.groupedFindings.set(sev, []);
      }
      this.groupedFindings.get(sev)!.push(f);
    }
  }
}

class SeverityGroupItem extends vscode.TreeItem {
  constructor(
    public readonly severity: string,
    count: number,
  ) {
    const label = SEVERITY_LABELS[severity] ?? severity;
    super(label, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${count}`;
    this.iconPath = SEVERITY_ICONS[severity] ?? SEVERITY_ICONS.info;
    this.contextValue = "severityGroup";
  }
}

export class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);

    this.description = `${relativePath(finding.filePath)}:${finding.startLine}`;
    this.tooltip = new vscode.MarkdownString(buildFindingTooltip(finding));
    this.contextValue = "finding";

    // Click to navigate to the finding location
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
  const sev = (finding.policySeverityOverride ?? finding.severity) as string;
  const lines = [
    `**${finding.title}**`,
    "",
    `$(${sev === "critical" || sev === "high" ? "error" : sev === "medium" ? "warning" : "info"}) **${sev.toUpperCase()}** \u00b7 \`${finding.ruleId}\``,
    "",
    finding.message,
  ];

  if (finding.remediationGuidance) {
    lines.push("", "---", "", `**Remediation:** ${finding.remediationGuidance}`);
  }

  lines.push("", `\`${finding.id}\``);
  return lines.join("\n");
}

function relativePath(filePath: string): string {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) return filePath;

  for (const folder of workspaceFolders) {
    if (filePath.startsWith(folder.uri.fsPath)) {
      return filePath.slice(folder.uri.fsPath.length + 1);
    }
  }

  return filePath;
}
