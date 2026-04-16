import { execFile, execFileSync } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { getSemgrepPath, waitForSemgrep } from "./semgrep-downloader";

export interface VardionixResult {
  success: boolean;
  data: unknown;
  error?: string;
}

/**
 * Find the vardionix CLI binary.
 * Search order:
 * 1. Bundled alongside extension (dist/cli.js)
 * 2. Monorepo layout (../cli/dist/index.js)
 * 3. npx vardionix (globally installed)
 */
function findCli(): { command: string; args: string[] } {
  // 1. Bundled alongside this extension
  const extensionDir = path.dirname(path.dirname(__filename));
  const bundledCli = path.join(extensionDir, "dist", "cli.js");
  if (fs.existsSync(bundledCli)) {
    return { command: "node", args: [bundledCli] };
  }

  // 2. Monorepo: extension is at packages/vscode-extension, CLI at packages/cli
  const monorepoCliPath = path.join(
    extensionDir,
    "..",
    "cli",
    "dist",
    "index.js",
  );
  if (fs.existsSync(monorepoCliPath)) {
    return { command: "node", args: [monorepoCliPath] };
  }

  // 3. Try npx/global vardionix
  try {
    execFileSync("npx", ["vardionix", "--version"], {
      stdio: "pipe",
      timeout: 10_000,
    });
    return { command: "npx", args: ["vardionix"] };
  } catch {
    // not available
  }

  // 4. Fallback: assume monorepo path even if not found
  return { command: "node", args: [monorepoCliPath] };
}

/**
 * Run a vardionix CLI command and return parsed JSON output.
 * Waits for Semgrep binary to be ready before executing.
 */
export async function runVardionix(
  args: string[],
  cwd: string,
): Promise<VardionixResult> {
  // Wait for semgrep download to complete (no-op if already ready)
  await waitForSemgrep();

  return new Promise((resolve) => {
    const cli = findCli();
    const semgrepPath = getSemgrepPath();

    execFile(
      cli.command,
      [...cli.args, ...args, "--json"],
      {
        cwd,
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
        env: {
          ...process.env,
          FORCE_COLOR: "0",
          NO_COLOR: "1",
          ...(semgrepPath !== "semgrep" ? { VARDIONIX_SEMGREP_PATH: semgrepPath } : {}),
        },
      },
      (error, stdout, stderr) => {
        if (error && !stdout) {
          resolve({
            success: false,
            data: null,
            error:
              stderr ||
              (error instanceof Error ? error.message : String(error)) ||
              "Vardionix CLI failed to start.",
          });
          return;
        }

        try {
          const data = JSON.parse(stdout);
          resolve({ success: true, data });
        } catch {
          // Not JSON - return raw text
          resolve({
            success: true,
            data: stdout.trim() || stderr.trim(),
          });
        }
      },
    );
  });
}
