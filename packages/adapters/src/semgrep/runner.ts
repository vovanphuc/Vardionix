import { execFile, execSync } from "node:child_process";
import type { SemgrepJsonOutput } from "./types.js";

export class SemgrepNotInstalledError extends Error {
  constructor() {
    super(
      [
        "Semgrep is not installed or not found in PATH.",
        "",
        "Install Semgrep using one of the following methods:",
        "  pip install semgrep",
        "  brew install semgrep",
        "  docker run -v $(pwd):/src semgrep/semgrep semgrep scan",
        "",
        "Or specify a custom path with --semgrep-path",
      ].join("\n"),
    );
    this.name = "SemgrepNotInstalledError";
  }
}

export class SemgrepScanError extends Error {
  constructor(
    message: string,
    public readonly stderr: string,
    public readonly exitCode: number | null,
  ) {
    super(message);
    this.name = "SemgrepScanError";
  }
}

export interface SemgrepRunnerOptions {
  semgrepPath?: string;
  timeout?: number;
}

export class SemgrepRunner {
  private semgrepPath: string;
  private timeout: number;

  constructor(options: SemgrepRunnerOptions = {}) {
    this.semgrepPath = options.semgrepPath ?? "semgrep";
    this.timeout = options.timeout ?? 300_000;
  }

  checkInstalled(): boolean {
    try {
      execSync(`${this.semgrepPath} --version`, {
        stdio: "pipe",
        timeout: 10_000,
      });
      return true;
    } catch {
      return false;
    }
  }

  async scan(args: {
    targets: string[];
    ruleset: string;
    extraArgs?: string[];
  }): Promise<SemgrepJsonOutput> {
    if (!this.checkInstalled()) {
      throw new SemgrepNotInstalledError();
    }

    const cmdArgs = [
      "scan",
      "--json",
      "--config",
      args.ruleset,
      ...(args.extraArgs ?? []),
      ...args.targets,
    ];

    return new Promise((resolve, reject) => {
      execFile(
        this.semgrepPath,
        cmdArgs,
        {
          timeout: this.timeout,
          maxBuffer: 50 * 1024 * 1024,
          env: {
            ...process.env,
            SEMGREP_SEND_METRICS: "off",
          },
        },
        (error, stdout, stderr) => {
          // Semgrep returns exit code 1 when findings exist, which is normal
          if (error && error.code !== undefined && error.code !== null) {
            const exitCode =
              typeof error.code === "number" ? error.code : null;
            // Exit code 1 = findings found (not an error)
            // Exit code 0 = no findings
            if (exitCode !== null && exitCode > 1) {
              reject(
                new SemgrepScanError(
                  `Semgrep scan failed with exit code ${exitCode}`,
                  stderr,
                  exitCode,
                ),
              );
              return;
            }
          }

          try {
            const output = JSON.parse(stdout) as SemgrepJsonOutput;
            resolve(output);
          } catch {
            reject(
              new SemgrepScanError(
                "Failed to parse Semgrep JSON output",
                stderr || stdout,
                null,
              ),
            );
          }
        },
      );
    });
  }
}
