import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";
import type * as vscode from "vscode";

const CLAUDE_CONFIG_PATH = join(homedir(), ".claude.json");
const CODEX_SETTINGS_PATH = join(homedir(), ".codex", "config.toml");
const MCP_SERVER_NAME = "vardionix";

export type McpClientTarget = "claude" | "codex";

interface McpServerConfig {
  command: string;
  args: string[];
  [key: string]: unknown;
}

interface ClaudeProjectConfig {
  mcpServers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

interface ClaudeSettings {
  mcpServers?: Record<string, McpServerConfig>;
  projects?: Record<string, ClaudeProjectConfig>;
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
  workspaceRoot?: string,
): McpRegistrationResult {
  const mcpServerPath = getMcpServerPath(context);
  if (!existsSync(mcpServerPath)) {
    throw new Error(`Bundled MCP server not found at ${mcpServerPath}`);
  }

  switch (target) {
    case "claude":
      return installClaudeRegistration(mcpServerPath, workspaceRoot);
    case "codex":
      return installCodexRegistration(mcpServerPath);
    default:
      throw new Error(`Unsupported MCP target: ${target satisfies never}`);
  }
}

export function verifyMcpServerRegistration(
  context: vscode.ExtensionContext,
  target: McpClientTarget,
  workspaceRoot?: string,
): boolean {
  const mcpServerPath = getMcpServerPath(context);
  if (!existsSync(mcpServerPath)) {
    return false;
  }

  switch (target) {
    case "claude":
      return verifyClaudeRegistration(mcpServerPath, workspaceRoot);
    case "codex":
      return verifyCodexRegistration(mcpServerPath);
    default:
      return false;
  }
}

function getMcpServerPath(context: vscode.ExtensionContext): string {
  return join(context.extensionPath, "dist", "mcp-server.js");
}

function installClaudeRegistration(
  mcpServerPath: string,
  workspaceRoot?: string,
): McpRegistrationResult {
  const claudeProjectPath = getClaudeProjectPath(workspaceRoot);
  const settings = readClaudeSettings();
  const projectEntry = settings.projects?.[claudeProjectPath] ?? {};
  const existing = projectEntry.mcpServers?.[MCP_SERVER_NAME];

  if (!settings.projects) {
    settings.projects = {};
  }
  if (!settings.projects[claudeProjectPath]) {
    settings.projects[claudeProjectPath] = {};
  }
  if (!settings.projects[claudeProjectPath].mcpServers) {
    settings.projects[claudeProjectPath].mcpServers = {};
  }

  settings.projects[claudeProjectPath].mcpServers![MCP_SERVER_NAME] = {
    command: "node",
    args: [mcpServerPath],
  };

  writeClaudeSettings(settings);

  return {
    target: "claude",
    configPath: CLAUDE_CONFIG_PATH,
    updated: !isClaudeRegistrationMatch(existing, mcpServerPath),
    verified: verifyClaudeRegistration(mcpServerPath, claudeProjectPath),
  };
}

function verifyClaudeRegistration(mcpServerPath: string, workspaceRoot?: string): boolean {
  const claudeProjectPath = getClaudeProjectPath(workspaceRoot);
  const settings = readClaudeSettings();
  return isClaudeRegistrationMatch(
    settings.projects?.[claudeProjectPath]?.mcpServers?.[MCP_SERVER_NAME],
    mcpServerPath,
  );
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
  if (!existsSync(CLAUDE_CONFIG_PATH)) {
    return {};
  }

  try {
    return JSON.parse(readFileSync(CLAUDE_CONFIG_PATH, "utf-8")) as ClaudeSettings;
  } catch {
    return {};
  }
}

function writeClaudeSettings(settings: ClaudeSettings): void {
  ensureParentDir(CLAUDE_CONFIG_PATH);
  writeFileSync(CLAUDE_CONFIG_PATH, JSON.stringify(settings, null, 2), "utf-8");
}

function getClaudeProjectPath(workspaceRoot?: string): string {
  if (!workspaceRoot) {
    throw new Error("Claude Code MCP registration requires an open workspace folder.");
  }
  return workspaceRoot;
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
