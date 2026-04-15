import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync, existsSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Build the extension
await esbuild.build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "dist/extension.js",
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node20",
  sourcemap: true,
  minify: false,
});

console.log("Build complete: dist/extension.js");

// Build a self-contained CLI bundle (re-bundle from CLI source with all deps inlined)
// better-sqlite3 is native so it must remain external and be copied
const cliEntry = join(__dirname, "..", "cli", "src", "index.ts");

if (existsSync(cliEntry)) {
  await esbuild.build({
    entryPoints: [cliEntry],
    bundle: true,
    outfile: "dist/cli.js",
    external: ["better-sqlite3"],
    format: "cjs",
    platform: "node",
    target: "node20",
    sourcemap: true,
    minify: false,
    banner: { js: "#!/usr/bin/env node" },
  });
  console.log("Bundled CLI: dist/cli.js");
} else {
  console.warn("WARNING: CLI source not found at", cliEntry);
  console.warn("Make sure you are building from the monorepo root.");
}

// Copy policies and rules alongside CLI for self-contained operation
const monorepoRoot = join(__dirname, "..", "..");

const policiessrc = join(monorepoRoot, "policies");
const policiesDest = join(__dirname, "dist", "policies");
if (existsSync(policiessrc)) {
  copyDirSync(policiessrc, policiesDest);
  console.log("Copied policies: dist/policies/");
}

const rulesSrc = join(monorepoRoot, "rules");
const rulesDest = join(__dirname, "dist", "rules");
if (existsSync(rulesSrc)) {
  copyDirSync(rulesSrc, rulesDest);
  console.log("Copied rules: dist/rules/");
}

// Copy better-sqlite3 native module into dist/ (not node_modules/ since vsce excludes it)
const betterSqliteDir = join(monorepoRoot, "node_modules", "better-sqlite3");
if (existsSync(betterSqliteDir)) {
  const targetDir = join(__dirname, "dist", "node_modules", "better-sqlite3");
  mkdirSync(targetDir, { recursive: true });

  // Copy package.json
  const pkgSrc = join(betterSqliteDir, "package.json");
  if (existsSync(pkgSrc)) {
    copyFileSync(pkgSrc, join(targetDir, "package.json"));
  }

  // Copy the prebuilt binding directory
  copyDirSync(join(betterSqliteDir, "build"), join(targetDir, "build"));
  // Copy lib directory
  copyDirSync(join(betterSqliteDir, "lib"), join(targetDir, "lib"));

  console.log("Copied better-sqlite3 native module to dist/node_modules/");
}

function copyDirSync(src, dest) {
  if (!existsSync(src)) return;
  mkdirSync(dest, { recursive: true });
  for (const entry of readdirSync(src)) {
    const srcPath = join(src, entry);
    const destPath = join(dest, entry);
    if (statSync(srcPath).isDirectory()) {
      copyDirSync(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
    }
  }
}
