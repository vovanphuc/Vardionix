import { execSync } from "node:child_process";

export function getWorkspaceRoot(): string {
  try {
    return execSync("git rev-parse --show-toplevel", {
      encoding: "utf-8",
      timeout: 5_000,
    }).trim();
  } catch {
    return process.cwd();
  }
}

export function getStagedFiles(): string[] {
  try {
    const output = execSync("git diff --cached --name-only --diff-filter=ACMR", {
      encoding: "utf-8",
      timeout: 10_000,
    }).trim();

    if (!output) return [];
    return output.split("\n").filter((f) => f.length > 0);
  } catch {
    return [];
  }
}

export function isGitRepo(): boolean {
  try {
    execSync("git rev-parse --git-dir", {
      stdio: "pipe",
      timeout: 5_000,
    });
    return true;
  } catch {
    return false;
  }
}
