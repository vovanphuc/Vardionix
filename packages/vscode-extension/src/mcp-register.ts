import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";
import type * as vscode from "vscode";

const CLAUDE_SETTINGS_PATH = join(homedir(), ".claude", "settings.json");
const CODEX_SETTINGS_PATH = join(homedir(), ".codex", "config.toml");
const MCP_SERVER_NAME = "vardionix";

export type McpClientTarget = "claude" | "codex";

interface McpServerConfig {
  command: string;
  args: string[];
  [key: string]: unknown;
}

interface ClaudeSettings {
  mcpServers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

export interface McpRegistrationResult {
  target: McpClientTarget;
  configPath: string;
  updated: boolean;
  verified: boolean;
}

export function getMcpTargetLabel(target: McpClientTarget): string {
  return target === "claude" ? "Claude Code" : "Codex";
}

export function installMcpServer(
  context: vscode.ExtensionContext,
  target: McpClientTarget,
): McpRegistrationResult {
  const mcpServerPath = getMcpServerPath(context);
  if (!existsSync(mcpServerPath)) {
    throw new Error(`Bundled MCP server not found at ${mcpServerPath}`);
  }

  switch (target) {
    case "claude":
      return installClaudeRegistration(mcpServerPath);
    case "codex":
      return installCodexRegistration(mcpServerPath);
    default:
      throw new Error(`Unsupported MCP target: ${target satisfies never}`);
  }
}

export function verifyMcpServerRegistration(
  context: vscode.ExtensionContext,
  target: McpClientTarget,
): boolean {
  const mcpServerPath = getMcpServerPath(context);
  if (!existsSync(mcpServerPath)) {
    return false;
  }

  switch (target) {
    case "claude":
      return verifyClaudeRegistration(mcpServerPath);
    case "codex":
      return verifyCodexRegistration(mcpServerPath);
    default:
      return false;
  }
}

function getMcpServerPath(context: vscode.ExtensionContext): string {
  return join(context.extensionPath, "dist", "mcp-server.js");
}

function installClaudeRegistration(mcpServerPath: string): McpRegistrationResult {
  const settings = readClaudeSettings();
  const existing = settings.mcpServers?.[MCP_SERVER_NAME];

  if (!settings.mcpServers) {
    settings.mcpServers = {};
  }

  settings.mcpServers[MCP_SERVER_NAME] = {
    command: "node",
    args: [mcpServerPath],
  };

  writeClaudeSettings(settings);

  return {
    target: "claude",
    configPath: CLAUDE_SETTINGS_PATH,
    updated: !isClaudeRegistrationMatch(existing, mcpServerPath),
    verified: verifyClaudeRegistration(mcpServerPath),
  };
}

function verifyClaudeRegistration(mcpServerPath: string): boolean {
  const settings = readClaudeSettings();
  return isClaudeRegistrationMatch(settings.mcpServers?.[MCP_SERVER_NAME], mcpServerPath);
}

function isClaudeRegistrationMatch(
  entry: McpServerConfig | undefined,
  mcpServerPath: string,
): boolean {
  return Boolean(
    entry &&
      entry.command === "node" &&
      Array.isArray(entry.args) &&
      entry.args.length === 1 &&
      entry.args[0] === mcpServerPath,
  );
}

function readClaudeSettings(): ClaudeSettings {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) {
    return {};
  }

  try {
    return JSON.parse(readFileSync(CLAUDE_SETTINGS_PATH, "utf-8")) as ClaudeSettings;
  } catch {
    return {};
  }
}

function writeClaudeSettings(settings: ClaudeSettings): void {
  ensureParentDir(CLAUDE_SETTINGS_PATH);
  writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2), "utf-8");
}

function installCodexRegistration(mcpServerPath: string): McpRegistrationResult {
  const current = readTextFile(CODEX_SETTINGS_PATH);
  const next = upsertCodexSection(current, buildCodexSection(mcpServerPath));

  ensureParentDir(CODEX_SETTINGS_PATH);
  writeFileSync(CODEX_SETTINGS_PATH, next, "utf-8");

  return {
    target: "codex",
    configPath: CODEX_SETTINGS_PATH,
    updated: normalizeLineEndings(current) !== normalizeLineEndings(next),
    verified: verifyCodexRegistration(mcpServerPath),
  };
}

function verifyCodexRegistration(mcpServerPath: string): boolean {
  if (!existsSync(CODEX_SETTINGS_PATH)) {
    return false;
  }

  const section = getTomlSection(readFileSync(CODEX_SETTINGS_PATH, "utf-8"), "mcp_servers.vardionix");
  if (!section) {
    return false;
  }

  return (
    section.some((line) => line.trim() === 'command = "node"') &&
    section.some((line) => line.trim() === `args = [${formatTomlString(mcpServerPath)}]`)
  );
}

function buildCodexSection(mcpServerPath: string): string[] {
  return [
    "[mcp_servers.vardionix]",
    'command = "node"',
    `args = [${formatTomlString(mcpServerPath)}]`,
  ];
}

function upsertCodexSection(content: string, sectionLines: string[]): string {
  const normalized = normalizeLineEndings(content);
  const lines = normalized.length > 0 ? normalized.split("\n") : [];
  const sectionName = "[mcp_servers.vardionix]";
  const start = lines.findIndex((line) => line.trim() === sectionName);

  if (start === -1) {
    const prefix = normalized.trimEnd();
    return prefix.length > 0
      ? `${prefix}\n\n${sectionLines.join("\n")}\n`
      : `${sectionLines.join("\n")}\n`;
  }

  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s*\[.+\]\s*$/.test(lines[index])) {
      end = index;
      break;
    }
  }

  const before = lines.slice(0, start).join("\n").trimEnd();
  const after = lines.slice(end).join("\n").trimStart();
  const section = sectionLines.join("\n");

  if (before && after) {
    return `${before}\n\n${section}\n\n${after}\n`;
  }
  if (before) {
    return `${before}\n\n${section}\n`;
  }
  if (after) {
    return `${section}\n\n${after}\n`;
  }
  return `${section}\n`;
}

function getTomlSection(content: string, sectionName: string): string[] | null {
  const normalized = normalizeLineEndings(content);
  const lines = normalized.split("\n");
  const header = `[${sectionName}]`;
  const start = lines.findIndex((line) => line.trim() === header);

  if (start === -1) {
    return null;
  }

  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s*\[.+\]\s*$/.test(lines[index])) {
      end = index;
      break;
    }
  }

  return lines.slice(start + 1, end);
}

function formatTomlString(value: string): string {
  return JSON.stringify(value);
}

function readTextFile(path: string): string {
  if (!existsSync(path)) {
    return "";
  }
  return readFileSync(path, "utf-8");
}

function ensureParentDir(path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function normalizeLineEndings(content: string): string {
  return content.replace(/\r\n/g, "\n");
}
