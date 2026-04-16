import * as vscode from "vscode";
import { execFileSync, execFile } from "child_process";
import { existsSync, mkdirSync, chmodSync, createWriteStream, unlinkSync, renameSync } from "fs";
import { join } from "path";
import * as https from "https";
import * as http from "http";

/** Pinned Semgrep version for reproducibility */
const SEMGREP_VERSION = "1.67.0";

interface PlatformInfo {
  wheelPlatform: string;
  binaryName: string;
  binaryPathInWheel: string;
}

function getPlatformInfo(): PlatformInfo | null {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux" && arch === "x64") {
    return {
      wheelPlatform: "manylinux",
      binaryName: "osemgrep",
      binaryPathInWheel: "semgrep/bin/osemgrep",
    };
  }
  if (platform === "linux" && arch === "arm64") {
    return {
      wheelPlatform: "manylinux",
      binaryName: "osemgrep",
      binaryPathInWheel: "semgrep/bin/osemgrep",
    };
  }
  if (platform === "darwin" && arch === "x64") {
    return {
      wheelPlatform: "macosx",
      binaryName: "osemgrep",
      binaryPathInWheel: "semgrep/bin/osemgrep",
    };
  }
  if (platform === "darwin" && arch === "arm64") {
    return {
      wheelPlatform: "macosx",
      binaryName: "osemgrep",
      binaryPathInWheel: "semgrep/bin/osemgrep",
    };
  }
  if (platform === "win32" && arch === "x64") {
    return {
      wheelPlatform: "win",
      binaryName: "osemgrep.exe",
      binaryPathInWheel: "semgrep/bin/osemgrep.exe",
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
    // Match manylinux wheels (any glibc version)
    const archTag = arch === "x64" ? "x86_64" : "aarch64";
    return filename.includes("manylinux") && filename.includes(archTag);
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

/**
 * Extract a single file from a .whl (zip) archive using platform tools.
 */
function extractFromWheel(whlPath: string, entryPath: string, destDir: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const destFile = join(destDir, entryPath.split("/").pop()!);
    const isWin = process.platform === "win32";

    if (isWin) {
      // PowerShell: extract specific entry from zip
      const script = `
        Add-Type -AssemblyName System.IO.Compression.FileSystem;
        $zip = [System.IO.Compression.ZipFile]::OpenRead('${whlPath.replace(/'/g, "''")}');
        $entry = $zip.Entries | Where-Object { $_.FullName -eq '${entryPath}' };
        if ($entry) {
          [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, '${destFile.replace(/'/g, "''")}', $true);
        }
        $zip.Dispose();
      `;
      execFile("powershell", ["-NoProfile", "-Command", script], (err) => {
        if (err) reject(err);
        else resolve(destFile);
      });
    } else {
      // Unix: unzip specific entry
      execFile("unzip", ["-o", "-j", whlPath, entryPath, "-d", destDir], (err) => {
        if (err) reject(err);
        else resolve(destFile);
      });
    }
  });
}

/**
 * Check if system Semgrep is available.
 */
function checkSystemSemgrep(semgrepPath: string): boolean {
  try {
    execFileSync(semgrepPath, ["--version"], { stdio: "pipe", timeout: 10_000 });
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

  for (const entry of data.urls) {
    if (matchesWheel(entry.filename, platformInfo)) {
      return entry.url;
    }
  }

  throw new Error(
    `No Semgrep wheel found for ${process.platform}/${process.arch} (version ${version})`
  );
}

// Module-level state: the resolved semgrep path and a ready promise
let resolvedSemgrepPath: string = "semgrep";
let semgrepReadyPromise: Promise<void> | null = null;

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

/**
 * Ensure Semgrep binary is available. Downloads if necessary.
 * Call this from extension activate().
 */
export function ensureSemgrep(globalStorageUri: vscode.Uri): Promise<void> {
  semgrepReadyPromise = doEnsureSemgrep(globalStorageUri);
  return semgrepReadyPromise;
}

async function doEnsureSemgrep(globalStorageUri: vscode.Uri): Promise<void> {
  const config = vscode.workspace.getConfiguration("vardionix");
  const configuredPath = config.get<string>("semgrepPath", "semgrep");

  // 1. If user explicitly configured a custom path, trust it
  if (configuredPath !== "semgrep") {
    resolvedSemgrepPath = configuredPath;
    return;
  }

  // 2. Check if system semgrep is available
  if (checkSystemSemgrep("semgrep")) {
    resolvedSemgrepPath = "semgrep";
    return;
  }

  // 3. Check if we already downloaded it
  const storageDir = globalStorageUri.fsPath;
  const semgrepDir = join(storageDir, "semgrep");
  const platformInfo = getPlatformInfo();

  if (!platformInfo) {
    vscode.window.showWarningMessage(
      `Vardionix: Unsupported platform (${process.platform}/${process.arch}). Please install Semgrep manually: pip install semgrep`
    );
    return;
  }

  const binaryPath = join(semgrepDir, platformInfo.binaryName);

  if (existsSync(binaryPath)) {
    resolvedSemgrepPath = binaryPath;
    return;
  }

  // 4. Download from PyPI
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix: Setting up Semgrep...",
      cancellable: false,
    },
    async (progress) => {
      try {
        mkdirSync(semgrepDir, { recursive: true });

        progress.report({ message: "Fetching download info...", increment: 0 });
        const wheelUrl = await fetchWheelUrl(SEMGREP_VERSION, platformInfo);

        const whlFile = join(semgrepDir, "semgrep.whl");

        progress.report({ message: "Downloading Semgrep binary...", increment: 10 });
        await downloadFile(wheelUrl, whlFile, (pct) => {
          progress.report({
            message: `Downloading Semgrep binary... ${pct}%`,
            increment: 0,
          });
        });

        progress.report({ message: "Extracting binary...", increment: 70 });
        const extractedPath = await extractFromWheel(
          whlFile,
          platformInfo.binaryPathInWheel,
          semgrepDir,
        );

        // Make executable on Unix
        if (process.platform !== "win32") {
          chmodSync(extractedPath, 0o755);
        }

        // Rename to expected name if different
        if (extractedPath !== binaryPath) {
          renameSync(extractedPath, binaryPath);
        }

        // Clean up wheel file
        try { unlinkSync(whlFile); } catch { /* ignore */ }

        // Verify the binary works
        try {
          execFileSync(binaryPath, ["--version"], { stdio: "pipe", timeout: 10_000 });
        } catch {
          vscode.window.showWarningMessage(
            "Vardionix: Downloaded Semgrep binary could not be executed. Please install Semgrep manually: pip install semgrep"
          );
          return;
        }

        resolvedSemgrepPath = binaryPath;
        progress.report({ message: "Semgrep ready!", increment: 100 });

        vscode.window.showInformationMessage(
          `Vardionix: Semgrep ${SEMGREP_VERSION} installed successfully.`
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showWarningMessage(
          `Vardionix: Could not download Semgrep automatically. ${msg}. Please install manually: pip install semgrep`
        );
      }
    },
  );
}
