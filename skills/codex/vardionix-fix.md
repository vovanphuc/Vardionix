# Vardionix Security Fix

This skill generates and validates security fixes using Vardionix.

## Workflow

1. Get fix context with `finding_fix` or `vardionix agent codex fix`.
2. Get policy guidance for the finding if needed.
3. Read the affected source file.
4. Generate a minimal, correct fix.
5. Apply the fix.
6. Re-scan the affected file with `semgrep_scan` or `vardionix scan file`.
7. Confirm the target finding is resolved and note any remaining follow-up work.

## Usage

```
/vardionix-fix F-abc123def456
/vardionix-fix --severity high --limit 5
```

## Guidelines

- Generate the smallest possible fix.
- Do not refactor surrounding code.
- Follow internal policy remediation guidance.
- Validate all fixes before reporting success.
- If validation fails, report the failure and suggest alternatives.
