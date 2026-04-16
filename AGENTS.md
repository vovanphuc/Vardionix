# Repository Guidelines

## Project Structure & Module Organization
`Vardionix` is a Node.js 22+ TypeScript monorepo using npm workspaces. Core packages live in `packages/`: `cli`, `mcp-server`, `core`, `adapters`, `store`, `schemas`, and `vscode-extension`. Source files are typically under `packages/*/src`, tests live beside each package in `packages/*/__tests__`, shared fixtures are in `__fixtures__`, and contributor-facing docs are in `docs/`. Security content and agent assets are kept in `policies/`, `rules/`, `prompts/`, and `skills/`.

The current architecture separates scan results into two tracks:
- Active findings: findings that survive filtering and enter CLI/MCP/VS Code triage flows
- Excluded findings: findings filtered out by deterministic rules or confidence thresholds, stored separately for audit/debugging

Keep package boundaries clean:
- `@vardionix/schemas`: shared contracts for active findings, excluded findings, and scan summaries
- `@vardionix/store`: SQLite persistence for active findings and excluded findings
- `@vardionix/adapters`: Semgrep parsing/normalization, policy enrichment, and filtering
- `@vardionix/core`: app context and scan/explain/patch orchestration
- `cli`, `mcp-server`, `vscode-extension`: thin surfaces over the shared core

## Build, Test, and Development Commands
Run `npm install` once to install workspace dependencies. Use `npm run typecheck` to verify the TypeScript project graph, `npm test` to run the Vitest suite, and `npm run build` to run typecheck first and then bundle all packages. `npm run clean` removes package build output from `packages/*/dist`.

Useful manual checks:
- `npx vardionix scan file <path>`
- `npx vardionix findings list`
- `npx vardionix findings list --excluded`
- `node packages/mcp-server/dist/index.js`

## Coding Style & Naming Conventions
Follow the existing TypeScript ESM style: 2-space indentation, double quotes, trailing commas where multiline, and explicit `.js` import extensions in emitted-module imports. Use `PascalCase` for exported types/classes, `camelCase` for functions and variables, and kebab-case for filenames such as `scan-orchestrator.ts`.

Model intent explicitly:
- Use discriminated finding types (`kind: "active"` vs `kind: "excluded"`) instead of boolean state flags
- Keep excluded-finding behavior out of default active-finding flows
- Treat CLI/MCP/VS Code as consumers of shared contracts, not places to invent parallel data shapes

## Testing Guidelines
Vitest is the test runner. Add or update `*.test.ts` files under the relevant package’s `__tests__` directory, for example `packages/store/__tests__/findings-store.test.ts`. Cover the changed behavior directly, especially parser, policy, filtering, and persistence changes. No coverage gate is configured today, so contributors should treat changed-path coverage as required before opening a PR.

When touching scan behavior, prefer tests for:
- confidence handling when metadata is absent
- separation of active vs excluded findings
- scan summary shape and counts
- CLI/MCP behavior that depends on excluded findings being hidden by default

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit prefixes such as `feat:` and `fix:`; keep that format and make scopes descriptive when useful. PRs should include a short summary, affected packages, and the commands you ran locally, such as `npm test`, `npm run typecheck`, and `npm run build`. Include screenshots or GIFs for `packages/vscode-extension` UI changes, and call out any updates to policies, Semgrep behavior, excluded-finding behavior, or MCP tool contracts.

## Security & Configuration Tips
Local configuration lives at `~/.vardionix/config.yaml`. Semgrep is required for scanning workflows, and the GitHub workflow in `.github/workflows/security-review.yml` builds the repo and scans changed files on pull requests. Avoid committing machine-specific paths, generated `dist/` changes unless intentionally releasing build artifacts, local database state, or reintroducing remote-validation / Backend.AI surfaces unless the subsystem is fully implemented again.
