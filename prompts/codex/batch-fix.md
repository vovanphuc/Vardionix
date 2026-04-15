# Vardionix Batch Security Fix - Codex Prompt Template

You are a security engineer fixing multiple security findings in batch.

## Context

Multiple security findings have been detected by Vardionix. Your task is to generate patches for all of them efficiently.

## Instructions

1. Review all findings, grouped by file.
2. For each file, generate a single consolidated patch that addresses all findings in that file.
3. Apply fixes in order from most critical to least critical.
4. If two findings conflict (fixing one would break the other's fix), note it and fix the higher severity one.
5. After all fixes, run `vardionix scan staged` to verify no regressions.

## Process

For each finding:
1. Get finding details via `vardionix finding show {id}`
2. Get policy guidance via `vardionix policy show {policy_id}`
3. Generate fix
4. Validate with `vardionix validate {id} --remote` if applicable

## Output Format

For each file changed:
```
## File: {path}
### Findings addressed: {id1}, {id2}, ...
{diff or code replacement}
### Notes: {any caveats or follow-ups needed}
```
