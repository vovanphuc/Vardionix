import * as vscode from "vscode";
import { execFileSync } from "child_process";
import { existsSync, mkdirSync, chmodSync, createWriteStream, unlinkSync, renameSync } from "fs";
import { join, dirname } from "path";
import * as https from "https";
import * as http from "http";

const yauzl: any = require("yauzl");

/** Pinned Semgrep version for reproducibility */
const SEMGREP_VERSION = "1.159.0";

/** Methods to try installing semgrep, in priority order */
const INSTALL_METHODS = [
  { name: "pipx", commands: [["pipx", "install", `semgrep==${SEMGREP_VERSION}`]] },
  { name: "pip", commands: [["pip3", "install", "--user", `semgrep==${SEMGREP_VERSION}`], ["pip", "install", "--user", `semgrep==${SEMGREP_VERSION}`]] },
  { name: "brew", commands: [["brew", "install", "semgrep"]] },
] as const;

interface PlatformInfo {
  wheelPlatform: string;
  binaryName: string;
  binaryCandidates: string[];
}

function getPlatformInfo(): PlatformInfo | null {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux" && (arch === "x64" || arch === "arm64")) {
    return {
      wheelPlatform: "manylinux",
      binaryName: "semgrep-core",
      binaryCandidates: ["semgrep-core", "osemgrep", "semgrep"],
    };
  }
  if (platform === "darwin" && (arch === "x64" || arch === "arm64")) {
    return {
      wheelPlatform: "macosx",
      binaryName: "semgrep-core",
      binaryCandidates: ["semgrep-core", "osemgrep", "semgrep"],
    };
  }
  if (platform === "win32" && arch === "x64") {
    return {
      wheelPlatform: "win",
      binaryName: "semgrep-core.exe",
      binaryCandidates: ["semgrep-core.exe", "osemgrep.exe", "semgrep.exe"],
    };
  }

  return null;
}

/**
 * Match a wheel filename to the current platform and architecture.
 */
function matchesWheel(filename: string, info: PlatformInfo): boolean {
  if (!filename.endsWith(".whl")) return false;

  const arch = process.arch;
  const platform = process.platform;

  if (platform === "linux") {
    // Match manylinux or musllinux wheels
    const archTag = arch === "x64" ? "x86_64" : "aarch64";
    const isLinuxWheel = filename.includes("manylinux") || filename.includes("musllinux");
    return isLinuxWheel && filename.includes(archTag);
  }

  if (platform === "darwin") {
    const archTag = arch === "x64" ? "x86_64" : "arm64";
    return filename.includes("macosx") && filename.includes(archTag);
  }

  if (platform === "win32") {
    return filename.includes("win") && filename.includes("amd64");
  }

  return false;
}

/**
 * Fetch JSON from a URL, following redirects.
 */
function fetchJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https") ? https.get : http.get;
    get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchJson(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        return;
      }
      let data = "";
      res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
      res.on("error", reject);
    }).on("error", reject);
  });
}

/**
 * Download a file from a URL, following redirects.
 */
function downloadFile(url: string, dest: string, onProgress?: (pct: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https") ? https.get : http.get;
    get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        downloadFile(res.headers.location, dest, onProgress).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
        return;
      }

      const totalSize = parseInt(res.headers["content-length"] ?? "0", 10);
      let downloaded = 0;
      const file = createWriteStream(dest);

      res.on("data", (chunk: Buffer) => {
        downloaded += chunk.length;
        if (totalSize > 0 && onProgress) {
          onProgress(Math.round((downloaded / totalSize) * 100));
        }
      });

      res.pipe(file);
      file.on("finish", () => { file.close(() => resolve()); });
      file.on("error", (err) => { file.close(); reject(err); });
      res.on("error", reject);
    }).on("error", reject);
  });
}

function openWheel(whlPath: string): Promise<any> {
  return new Promise((resolve, reject) => {
    yauzl.open(
      whlPath,
      {
        lazyEntries: true,
      },
      (error: Error | null, zipFile: any) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(zipFile);
      },
    );
  });
}

function closeWheel(zipFile: any): void {
  try {
    zipFile.close();
  } catch {
    // ignore close errors
  }
}

/**
 * Extract a single file from a .whl (zip) archive without relying on external tools.
 */
async function extractFromWheel(
  whlPath: string,
  entryPath: string,
  destDir: string,
): Promise<string> {
  const zipFile = await openWheel(whlPath);
  const destFile = join(destDir, entryPath.split("/").pop()!);

  return new Promise((resolve, reject) => {
    let settled = false;

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      closeWheel(zipFile);
      reject(error);
    };

    const succeed = () => {
      if (settled) return;
      settled = true;
      closeWheel(zipFile);
      resolve(destFile);
    };

    zipFile.on("error", (error: Error) => {
      fail(error);
    });

    zipFile.on("entry", (entry: any) => {
      if (entry.fileName !== entryPath) {
        zipFile.readEntry();
        return;
      }

      zipFile.openReadStream(entry, (error: Error | null, readStream: NodeJS.ReadableStream | undefined) => {
        if (error) {
          fail(error);
          return;
        }
        if (!readStream) {
          fail(new Error(`Could not open ${entryPath} from downloaded Semgrep wheel`));
          return;
        }

        const output = createWriteStream(destFile);

        output.on("error", (streamError) => {
          fail(streamError);
        });
        readStream.on("error", (streamError) => {
          fail(streamError);
        });
        output.on("finish", () => {
          succeed();
        });

        readStream.pipe(output);
      });
    });

    zipFile.on("end", () => {
      if (!settled) {
        fail(new Error(`Could not find ${entryPath} in downloaded Semgrep wheel`));
      }
    });

    zipFile.readEntry();
  });
}

function listWheelEntries(whlPath: string): Promise<string[]> {
  return openWheel(whlPath).then((zipFile) => new Promise((resolve, reject) => {
    const entries: string[] = [];

    zipFile.on("error", (error: Error) => {
      closeWheel(zipFile);
      reject(error);
    });

    zipFile.on("entry", (entry: any) => {
      entries.push(entry.fileName);
      zipFile.readEntry();
    });

    zipFile.on("end", () => {
      closeWheel(zipFile);
      resolve(entries);
    });

    zipFile.readEntry();
  }));
}

async function findBinaryEntryInWheel(
  whlPath: string,
  platformInfo: PlatformInfo,
): Promise<string> {
  const entries = await listWheelEntries(whlPath);
  const candidates = entries
    .filter((entry) => !entry.endsWith("/"))
    .filter((entry) => {
      const basename = entry.split("/").pop();
      return basename ? platformInfo.binaryCandidates.includes(basename) : false;
    })
    .sort((left, right) => scoreWheelEntry(left) - scoreWheelEntry(right));

  if (candidates.length === 0) {
    throw new Error(
      `No Semgrep executable found in downloaded wheel. Expected one of: ${platformInfo.binaryCandidates.join(", ")}`,
    );
  }

  return candidates[0];
}

function scoreWheelEntry(entry: string): number {
  if (entry.includes("/semgrep/bin/")) return 0;
  if (entry.includes("/bin/")) return 1;
  if (entry.includes(".data/scripts/")) return 2;
  return 3;
}

/**
 * Extract all shared libraries from the wheel that sit alongside the binary.
 * semgrep-core needs libs/ directory (dylibs/so files) at runtime.
 */
async function extractLibsFromWheel(
  whlPath: string,
  binaryEntryPath: string,
  destDir: string,
): Promise<void> {
  // Find the parent dir of the binary inside the wheel
  // e.g. "semgrep-1.159.0.data/purelib/semgrep/bin/semgrep-core"
  //    → "semgrep-1.159.0.data/purelib/semgrep/bin/"
  const binaryDir = binaryEntryPath.substring(0, binaryEntryPath.lastIndexOf("/") + 1);
  const libsPrefix = binaryDir + "libs/";

  const entries = await listWheelEntries(whlPath);
  const libEntries = entries.filter(
    (e) => e.startsWith(libsPrefix) && !e.endsWith("/"),
  );

  if (libEntries.length === 0) return;

  // Create libs/ directory in dest
  const libsDir = join(destDir, "libs");
  mkdirSync(libsDir, { recursive: true });

  for (const entry of libEntries) {
    const filename = entry.split("/").pop()!;
    const destPath = join(libsDir, filename);

    // Skip if already extracted
    if (existsSync(destPath)) continue;

    await extractFromWheel(whlPath, entry, libsDir);

    // Make libs executable on Unix
    if (process.platform !== "win32") {
      try { chmodSync(destPath, 0o755); } catch { /* ignore */ }
    }
  }
}

/**
 * Check if a Semgrep binary is executable.
 * For system `semgrep` (Python CLI): runs `semgrep --version`.
 * For downloaded `semgrep-core` (OCaml binary): runs `semgrep-core -version`
 * which is the OCaml convention (single dash).
 */
function checkSystemSemgrep(semgrepPath: string): boolean {
  try {
    const env: Record<string, string | undefined> = { ...process.env };

    // If this is a downloaded binary, set library path
    if (semgrepPath !== "semgrep") {
      const libsDir = join(dirname(semgrepPath), "libs");
      if (existsSync(libsDir)) {
        Object.assign(env, buildSemgrepEnv(libsDir));
      }
    }

    // semgrep-core uses OCaml convention: -version (single dash)
    // System semgrep (Python) uses --version (double dash)
    const isCore = semgrepPath.includes("semgrep-core");
    const versionFlag = isCore ? "-version" : "--version";

    execFileSync(semgrepPath, [versionFlag], { stdio: "pipe", timeout: 10_000, env });
    return true;
  } catch {
    return false;
  }
}

/**
 * Fetch the download URL for the platform-specific wheel from PyPI.
 */
async function fetchWheelUrl(version: string, platformInfo: PlatformInfo): Promise<string> {
  const apiUrl = `https://pypi.org/pypi/semgrep/${version}/json`;
  const data = await fetchJson(apiUrl) as {
    urls: Array<{ filename: string; url: string }>;
  };

  // Collect all matching wheels, prefer manylinux over musllinux
  const matches = data.urls
    .filter((entry) => matchesWheel(entry.filename, platformInfo))
    .sort((a, b) => {
      const aScore = a.filename.includes("manylinux") ? 0 : 1;
      const bScore = b.filename.includes("manylinux") ? 0 : 1;
      return aScore - bScore;
    });

  if (matches.length > 0) {
    return matches[0].url;
  }

  throw new Error(
    `No Semgrep wheel found for ${process.platform}/${process.arch} (version ${version})`
  );
}

/**
 * Build environment variables needed for semgrep-core to find its shared libraries.
 */
export function buildSemgrepEnv(libsDir: string): Record<string, string> {
  if (!existsSync(libsDir)) return {};

  if (process.platform === "darwin") {
    const existing = process.env.DYLD_LIBRARY_PATH ?? "";
    return {
      DYLD_LIBRARY_PATH: existing ? `${libsDir}:${existing}` : libsDir,
    };
  }

  if (process.platform === "linux") {
    const existing = process.env.LD_LIBRARY_PATH ?? "";
    return {
      LD_LIBRARY_PATH: existing ? `${libsDir}:${existing}` : libsDir,
    };
  }

  if (process.platform === "win32") {
    const existing = process.env.PATH ?? "";
    return {
      PATH: `${libsDir};${existing}`,
    };
  }

  return {};
}

/**
 * Get the libs directory path for the downloaded semgrep.
 */
export function getSemgrepLibsDir(): string | null {
  if (resolvedSemgrepPath === "semgrep") return null;
  const dir = dirname(resolvedSemgrepPath);
  const libsDir = join(dir, "libs");
  return existsSync(libsDir) ? libsDir : null;
}

// Module-level state: the resolved semgrep path and a ready promise
let resolvedSemgrepPath: string = "semgrep";
let semgrepReadyPromise: Promise<void> | null = null;
let lastSemgrepSetupError: string | undefined;

/**
 * Get the resolved semgrep binary path.
 */
export function getSemgrepPath(): string {
  return resolvedSemgrepPath;
}

/**
 * Wait until semgrep is ready (downloaded or found on system).
 */
export function waitForSemgrep(): Promise<void> {
  return semgrepReadyPromise ?? Promise.resolve();
}

export function getLastSemgrepSetupError(): string | undefined {
  return lastSemgrepSetupError;
}

export function hasSemgrepAvailable(): boolean {
  if (resolvedSemgrepPath === "semgrep") {
    return checkSystemSemgrep("semgrep");
  }

  return existsSync(resolvedSemgrepPath) && checkSystemSemgrep(resolvedSemgrepPath);
}

/**
 * Ensure Semgrep binary is available. Downloads if necessary.
 * Call this from extension activate().
 */
export function ensureSemgrep(globalStorageUri: vscode.Uri): Promise<void> {
  if (hasSemgrepAvailable()) {
    lastSemgrepSetupError = undefined;
    return Promise.resolve();
  }

  if (semgrepReadyPromise) {
    return semgrepReadyPromise;
  }

  semgrepReadyPromise = doEnsureSemgrep(globalStorageUri).finally(() => {
    if (!hasSemgrepAvailable()) {
      semgrepReadyPromise = null;
    }
  });
  return semgrepReadyPromise;
}

/**
 * Try to install semgrep using a package manager (pipx, pip, brew).
 * Returns true if semgrep becomes available on PATH after install.
 */
function tryPackageManagerInstall(
  method: string,
  commands: ReadonlyArray<readonly string[]>,
  progress: vscode.Progress<{ message?: string; increment?: number }>,
): boolean {
  for (const cmd of commands) {
    const [bin, ...args] = cmd;
    try {
      // Check if the package manager exists
      execFileSync(bin, ["--version"], { stdio: "pipe", timeout: 10_000 });
    } catch {
      continue; // This package manager is not installed
    }

    try {
      progress.report({ message: `Installing via ${method}...` });
      execFileSync(bin, [...args], {
        stdio: "pipe",
        timeout: 300_000, // 5 min for install
        env: { ...process.env },
      });

      // Check if semgrep is now available
      if (checkSystemSemgrep("semgrep")) {
        return true;
      }
    } catch {
      // Install failed, try next method
    }
  }
  return false;
}

async function doEnsureSemgrep(globalStorageUri: vscode.Uri): Promise<void> {
  lastSemgrepSetupError = undefined;
  const config = vscode.workspace.getConfiguration("vardionix");
  const configuredPath = config.get<string>("semgrepPath", "semgrep");

  // 1. If user explicitly configured a custom path, trust it
  if (configuredPath !== "semgrep") {
    if (checkSystemSemgrep(configuredPath)) {
      resolvedSemgrepPath = configuredPath;
      return;
    }

    vscode.window.showWarningMessage(
      `Vardionix: Configured Semgrep path "${configuredPath}" is not executable. Falling back to automatic setup.`,
    );
  }

  // 2. Check if system semgrep is available
  if (checkSystemSemgrep("semgrep")) {
    resolvedSemgrepPath = "semgrep";
    return;
  }

  // 3. Try installing via package managers (pipx → pip → brew)
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix: Setting up Semgrep...",
      cancellable: false,
    },
    async (progress) => {
      for (const method of INSTALL_METHODS) {
        progress.report({ message: `Trying ${method.name}...` });

        if (tryPackageManagerInstall(method.name, method.commands, progress)) {
          resolvedSemgrepPath = "semgrep";
          lastSemgrepSetupError = undefined;
          progress.report({ message: "Semgrep ready!", increment: 100 });
          vscode.window.showInformationMessage(
            `Vardionix: Semgrep installed successfully via ${method.name}.`,
          );
          return;
        }
      }

      // 4. All package managers failed
      const installHints = process.platform === "darwin"
        ? "brew install semgrep  or  pip3 install semgrep"
        : "pip3 install semgrep  or  pipx install semgrep";

      lastSemgrepSetupError =
        `Could not install Semgrep automatically (no pipx, pip, or brew found). Install manually with: ${installHints}`;
      vscode.window.showWarningMessage(`Vardionix: ${lastSemgrepSetupError}`);
    },
  );
}
