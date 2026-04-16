# Changelog

## 0.1.6 (2026-04-16)

- Add manual MCP install and verify actions in the VS Code UI for Claude Code and Codex
- Bundle the MCP server with the extension so the generated config points at a self-contained server path
- Fix stale findings persisting after a clean rescan and improve Semgrep auto-setup robustness

## 0.1.5 (2026-04-16)

- Retry Semgrep auto-setup before scans and show clearer scan errors outside Git repositories
- Avoid `sql.js` asm out-of-memory crashes by switching to the memory-growth build
- Stop passing `--json` to dismiss commands in the VS Code extension runner

## 0.1.4 (2026-04-16)

- Replace local SQLite storage from `better-sqlite3` to `sql.js` to keep Marketplace packaging cross-platform

## 0.1.0 (2026-04-15)

- Initial release
- Semgrep-based security scanning (file, staged, workspace)
- Findings tree view in sidebar
- Finding explanation with remediation guidance
- Finding dismissal workflow
- Policy lookup (OWASP Top 10, internal standards)
- Scan-on-save option
- VS Code diagnostics integration
