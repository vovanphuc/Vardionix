import { execFile, execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, extname } from "node:path";
import type { SarifLog } from "./types.js";

export class CodeQLNotInstalledError extends Error {
  constructor() {
    super(
      [
        "CodeQL CLI is not installed or not found in PATH.",
        "",
        "Install CodeQL:",
        "  brew install codeql",
        "  or download from: https://github.com/github/codeql-action/releases",
        "",
        "Note: CodeQL requires GitHub Advanced Security license",
        "for scanning closed-source code.",
      ].join("\n"),
    );
    this.name = "CodeQLNotInstalledError";
  }
}

export class CodeQLScanError extends Error {
  constructor(
    message: string,
    public readonly stderr: string,
    public readonly phase: "database" | "analyze",
  ) {
    super(message);
    this.name = "CodeQLScanError";
  }
}

export interface CodeQLRunnerOptions {
  codeqlPath?: string;
  timeout?: number;
  querySuite?: string;
  threads?: number;
  ram?: number;
}

/** Map file extensions to CodeQL language identifiers */
const EXTENSION_TO_LANGUAGE: Record<string, string> = {
  ".js": "javascript-typescript",
  ".ts": "javascript-typescript",
  ".jsx": "javascript-typescript",
  ".tsx": "javascript-typescript",
  ".mjs": "javascript-typescript",
  ".cjs": "javascript-typescript",
  ".py": "python",
  ".go": "go",
  ".java": "java-kotlin",
  ".kt": "java-kotlin",
  ".rb": "ruby",
  ".cs": "csharp",
  ".cpp": "cpp",
  ".c": "cpp",
  ".swift": "swift",
};

/** Map CodeQL language to query suite prefix */
const LANGUAGE_SUITE_PREFIX: Record<string, string> = {
  "javascript-typescript": "javascript",
  python: "python",
  go: "go",
  "java-kotlin": "java",
  ruby: "ruby",
  csharp: "csharp",
  cpp: "cpp",
  swift: "swift",
};

export class CodeQLRunner {
  private codeqlPath: string;
  private timeout: number;
  private querySuite: string;
  private threads: number;
  private ram: number;

  constructor(options: CodeQLRunnerOptions = {}) {
    this.codeqlPath = options.codeqlPath ?? "codeql";
    this.timeout = options.timeout ?? 600_000;
    this.querySuite = options.querySuite ?? "security-extended";
    this.threads = options.threads ?? 0;
    this.ram = options.ram ?? 4096;
  }

  checkInstalled(): boolean {
    try {
      execFileSync(this.codeqlPath, ["version"], {
        stdio: "pipe",
        timeout: 10_000,
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Detect primary language from a source directory */
  static detectLanguage(sourceRoot: string): string | null {
    const counts: Record<string, number> = {};

    function walk(dir: string, depth: number) {
      if (depth > 3) return;
      try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          if (entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "node_modules") {
            walk(join(dir, entry.name), depth + 1);
          } else if (entry.isFile()) {
            const ext = extname(entry.name);
            const lang = EXTENSION_TO_LANGUAGE[ext];
            if (lang) counts[lang] = (counts[lang] ?? 0) + 1;
          }
        }
      } catch {
        /* ignore permission errors */
      }
    }

    walk(sourceRoot, 0);

    let best: string | null = null;
    let bestCount = 0;
    for (const [lang, count] of Object.entries(counts)) {
      if (count > bestCount) {
        best = lang;
        bestCount = count;
      }
    }
    return best;
  }

  async scan(args: {
    sourceRoot: string;
    language: string;
    buildCommand?: string;
  }): Promise<SarifLog> {
    if (!this.checkInstalled()) {
      throw new CodeQLNotInstalledError();
    }

    const tmpDir = mkdtempSync(join(tmpdir(), "vardionix-codeql-"));
    const dbPath = join(tmpDir, "db");
    const sarifPath = join(tmpDir, "results.sarif");

    try {
      await this.createDatabase(
        dbPath,
        args.sourceRoot,
        args.language,
        args.buildCommand,
      );

      await this.analyzeDatabase(dbPath, sarifPath, args.language);

      const content = await readFile(sarifPath, "utf-8");
      return JSON.parse(content) as SarifLog;
    } finally {
      try {
        rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        /* ignore cleanup errors */
      }
    }
  }

  private createDatabase(
    dbPath: string,
    sourceRoot: string,
    language: string,
    buildCommand?: string,
  ): Promise<void> {
    const cmdArgs = [
      "database",
      "create",
      dbPath,
      "--language",
      language,
      "--source-root",
      sourceRoot,
      "--threads",
      String(this.threads),
      `--ram=${this.ram}`,
      "--overwrite",
    ];

    if (buildCommand) {
      cmdArgs.push("--command", buildCommand);
    }

    return this.run(cmdArgs, "database");
  }

  private analyzeDatabase(
    dbPath: string,
    outputPath: string,
    language: string,
  ): Promise<void> {
    const prefix = LANGUAGE_SUITE_PREFIX[language] ?? language;
    const suite = `${prefix}-${this.querySuite}.qls`;

    const cmdArgs = [
      "database",
      "analyze",
      dbPath,
      suite,
      "--format",
      "sarif-latest",
      "--output",
      outputPath,
      "--threads",
      String(this.threads),
      `--ram=${this.ram}`,
    ];

    return this.run(cmdArgs, "analyze");
  }

  private run(
    args: string[],
    phase: "database" | "analyze",
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      execFile(
        this.codeqlPath,
        args,
        {
          timeout: this.timeout,
          maxBuffer: 50 * 1024 * 1024,
        },
        (error, _stdout, stderr) => {
          if (error) {
            reject(
              new CodeQLScanError(
                `CodeQL ${phase} failed: ${stderr || error.message}`,
                stderr,
                phase,
              ),
            );
          } else {
            resolve();
          }
        },
      );
    });
  }
}
