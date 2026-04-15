import * as vscode from "vscode";
import type { Finding } from "./diagnostics";

const SEVERITY_ICONS: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  info: "info",
};

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<FindingItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingItem | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];

  setFindings(findings: Finding[]): void {
    this.findings = findings.filter((f) => f.status === "open");
    this._onDidChangeTreeData.fire();
  }

  getFindings(): Finding[] {
    return this.findings;
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingItem): FindingItem[] {
    if (element) {
      return []; // No children for individual findings
    }

    if (this.findings.length === 0) {
      return [];
    }

    // Group by severity
    const groups = new Map<string, Finding[]>();
    const severityOrder = ["critical", "high", "medium", "low", "info"];

    for (const f of this.findings) {
      const sev = (f.policySeverityOverride ?? f.severity) as string;
      if (!groups.has(sev)) {
        groups.set(sev, []);
      }
      groups.get(sev)!.push(f);
    }

    const items: FindingItem[] = [];
    for (const sev of severityOrder) {
      const group = groups.get(sev);
      if (!group || group.length === 0) continue;

      for (const finding of group) {
        items.push(new FindingItem(finding));
      }
    }

    return items;
  }
}

export class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    const effectiveSev = (finding.policySeverityOverride ??
      finding.severity) as string;
    const label = `${effectiveSev.toUpperCase()} ${finding.title}`;

    super(label, vscode.TreeItemCollapsibleState.None);

    this.description = `${relativePath(finding.filePath)}:${finding.startLine}`;
    this.tooltip = finding.message;
    this.contextValue = "finding";

    const iconId = SEVERITY_ICONS[effectiveSev] ?? "info";
    this.iconPath = new vscode.ThemeIcon(iconId);

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
