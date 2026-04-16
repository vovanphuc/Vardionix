import * as vscode from "vscode";

let statusBarItem: vscode.StatusBarItem;

export function createStatusBar(): vscode.StatusBarItem {
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    50,
  );
  statusBarItem.command = "vardionix.listFindings";
  statusBarItem.name = "Vardionix Findings";
  updateStatusBar({});
  statusBarItem.show();
  return statusBarItem;
}

export function updateStatusBar(counts: Record<string, number>): void {
  if (!statusBarItem) return;

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const critical = (counts.critical ?? 0) + (counts.high ?? 0);
  const medium = counts.medium ?? 0;

  if (total === 0) {
    statusBarItem.text = "$(shield) Vardionix";
    statusBarItem.tooltip = "No security findings — click to scan";
    statusBarItem.backgroundColor = undefined;
    return;
  }

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (medium > 0) parts.push(`${medium} medium`);
  const low = total - critical - medium;
  if (low > 0) parts.push(`${low} low`);

  statusBarItem.text = `$(shield) ${total} finding${total !== 1 ? "s" : ""}`;
  statusBarItem.tooltip = `Vardionix: ${parts.join(", ")}`;

  if (critical > 0) {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground",
    );
  } else if (medium > 0) {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground",
    );
  } else {
    statusBarItem.backgroundColor = undefined;
  }
}

export function setStatusBarScanning(): void {
  if (!statusBarItem) return;
  statusBarItem.text = "$(loading~spin) Scanning...";
  statusBarItem.tooltip = "Vardionix: Security scan in progress";
  statusBarItem.backgroundColor = undefined;
}
