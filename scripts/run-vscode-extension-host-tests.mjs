import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runTests } from "@vscode/test-electron";

const repoRoot = resolve(process.cwd());
const extensionDevelopmentPath = resolve(repoRoot, "packages/vscode-extension");
const extensionTestsPath = resolve(extensionDevelopmentPath, "test-host", "index.cjs");

function execFileAsync(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || stdout || error.message));
        return;
      }
      resolvePromise({ stdout, stderr });
    });
  });
}

const tempHome = await mkdtemp(join(tmpdir(), "vardionix-vscode-host-"));

try {
  await mkdir(join(tempHome, ".vardionix"), { recursive: true });

  await execFileAsync(
    "npm",
    ["run", "build", "--workspace", "packages/vscode-extension"],
    {
      cwd: repoRoot,
      env: process.env,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );

  const exitCode = await runTests({
    extensionDevelopmentPath,
    extensionTestsPath,
    launchArgs: [repoRoot, "--disable-extensions"],
    extensionTestsEnv: {
      HOME: tempHome,
      NO_COLOR: "1",
      FORCE_COLOR: "0",
    },
  });

  process.exit(exitCode);
} finally {
  await rm(tempHome, { recursive: true, force: true });
}
