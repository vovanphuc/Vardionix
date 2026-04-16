import { execFile, execFileSync } from "node:child_process";
import type { TrivyJsonOutput } from "./types.js";

export class TrivyNotInstalledError extends Error {
  constructor() {
    super(
      [
        "Trivy is not installed or not found in PATH.",
        "",
        "Install Trivy:",
        "  brew install trivy",
        "  or: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
      ].join("\n"),
    );
    this.name = "TrivyNotInstalledError";
  }
}

export class TrivyScanError extends Error {
  constructor(
    message: string,
    public readonly stderr: string,
  ) {
    super(message);
    this.name = "TrivyScanError";
  }
}

export interface TrivyRunnerOptions {
  trivyPath?: string;
  timeout?: number;
  severityFilter?: string[];
  ignoreUnfixed?: boolean;
}

export class TrivyRunner {
  private trivyPath: string;
  private timeout: number;
  private severityFilter: string[];
  private ignoreUnfixed: boolean;

  constructor(options: TrivyRunnerOptions = {}) {
    this.trivyPath = options.trivyPath ?? "trivy";
    this.timeout = options.timeout ?? 120_000;
    this.severityFilter = options.severityFilter ?? [
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
    ];
    this.ignoreUnfixed = options.ignoreUnfixed ?? false;
  }

  checkInstalled(): boolean {
    try {
      execFileSync(this.trivyPath, ["--version"], {
        stdio: "pipe",
        timeout: 10_000,
      });
      return true;
    } catch {
      return false;
    }
  }

  async scan(target: string): Promise<TrivyJsonOutput> {
    if (!this.checkInstalled()) {
      throw new TrivyNotInstalledError();
    }

    const args = [
      "fs",
      "--scanners",
      "vuln",
      "--format",
      "json",
      "--severity",
      this.severityFilter.join(","),
      "--skip-dirs",
      "node_modules,.git,dist,.next,build,__pycache__,.venv",
    ];

    if (this.ignoreUnfixed) {
      args.push("--ignore-unfixed");
    }

    args.push(target);

    return new Promise((resolve, reject) => {
      execFile(
        this.trivyPath,
        args,
        {
          timeout: this.timeout,
          maxBuffer: 50 * 1024 * 1024,
        },
        (error, stdout, stderr) => {
          // Trivy returns exit code 0 even with findings by default
          if (error && !stdout) {
            reject(
              new TrivyScanError(
                `Trivy scan failed: ${stderr || error.message}`,
                stderr,
              ),
            );
            return;
          }

          try {
            const output = JSON.parse(stdout) as TrivyJsonOutput;
            resolve(output);
          } catch {
            reject(
              new TrivyScanError(
                "Failed to parse Trivy JSON output",
                stderr || stdout,
              ),
            );
          }
        },
      );
    });
  }
}
