# Vardionix Security Fix

This skill generates and validates security fixes using Vardionix.

## Workflow

1. Get finding details from Vardionix store.
2. Get policy guidance for the finding.
3. Read the affected source file.
4. Generate a minimal, correct fix.
5. Apply the fix.
6. Run `vardionix validate` to verify.
7. Run `vardionix scan file` on the fixed file to confirm the finding is resolved.

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
