# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
npm install              # Install all workspace dependencies
npm run build            # Build all packages (tsup)
npm test                 # Run all tests (vitest)
npm run test:watch       # Run tests in watch mode
npm run typecheck        # TypeScript type checking (tsc --build)
npm run clean            # Remove all dist/ directories

# Run a single test file
npx vitest run packages/adapters/__tests__/semgrep/parser.test.ts

# Run tests matching a pattern
npx vitest run -t "pattern"
```

## Prerequisites

- Node.js >= 22 (see `.nvmrc`)
- Semgrep installed (`pip install semgrep` or `brew install semgrep`) for scanning functionality

## Architecture

Vardionix is a monorepo (`npm workspaces`) implementing a unified DevSecOps tool layer. All clients (CLI, VS Code, Claude Code MCP, Codex) funnel through the same core logic.

### Package Dependency Layers

```
Layer 0:  @vardionix/schemas        (Zod schemas, zero internal deps)
Layer 1:  @vardionix/store           (SQLite persistence via better-sqlite3)
          @vardionix/adapters        (Semgrep runner/parser, policy store, finding filter)
Layer 2:  @vardionix/core            (orchestration: scan, explain, patch, validate)
Layer 3:  @vardionix/mcp-server      (MCP stdio server, thin wrapper over core)
          vardionix (CLI)            (commander-based CLI, thin wrapper over core)
```

Changes to lower layers affect everything above. `schemas` is the foundation — modify it carefully.

### Key Data Flow: Scan Pipeline

CLI/MCP request → `ScanOrchestrator.scan()` → `SemgrepRunner` (spawns `semgrep --json`) → `parseSemgrepOutput()` → `normalizeFindings()` (deterministic IDs: `F-` + SHA256 of ruleId:filePath:startLine) → `PolicyEnricher` → `filterFindings()` (confidence threshold 0.8) → `FindingsStore.upsertFindings()` (SQLite)

### MCP Server

The MCP server (`packages/mcp-server/src/server.ts`) registers 6 tools via `@modelcontextprotocol/sdk`. Each tool is in its own file under `packages/mcp-server/src/tools/`. It delegates all logic to `@vardionix/core` services.

### Storage

- Findings DB: `~/.vardionix/findings.db` (SQLite, WAL mode)
- Config: `~/.vardionix/config.yaml`
- Policies: `policies/` directory (YAML) + optional user policies

## Conventions

- ESM-only (`"type": "module"` in all packages)
- TypeScript with `NodeNext` module resolution
- Each package builds with `tsup` and exports from `dist/`
- Tests live in `packages/<name>/__tests__/` directories
- Test fixtures are in `__fixtures__/` at the repo root
- Schemas use Zod for runtime validation and type inference
- Finding IDs are deterministic (SHA256-based), enabling idempotent upserts

## VS Code Extension

The `packages/vscode-extension/` package is separate — it has its own `tsconfig.json` targeting VS Code APIs and is not built by the workspace `build` script. The pre-built `.vsix` is at the repo root.

## Custom Claude Commands

- `/security-review` (`.claude/commands/security-review.md`): 3-phase security review using vardionix scan + explain + policy tools

## Agent Workflow Prompts

- `prompts/claude/` — Claude triage and explain prompts
- `prompts/codex/` — Codex fix and batch-fix prompts
- `skills/` — Skill definitions for Claude and Codex agent workflows
