import type { JobTemplate } from "./types.js";

/**
 * Whitelisted job templates for Backend.AI execution.
 * Only these templates can be used for remote validation.
 */
export const ALLOWED_TEMPLATES: JobTemplate[] = [
  {
    id: "go-sec-validate",
    name: "Go Security Validation",
    description: "Run security validation for Go code changes",
    language: "go",
    parameters: [
      {
        name: "test_pattern",
        type: "string",
        required: false,
        description: "Go test pattern to run",
      },
    ],
  },
  {
    id: "python-sec-validate",
    name: "Python Security Validation",
    description: "Run security validation for Python code changes",
    language: "python",
    parameters: [
      {
        name: "test_pattern",
        type: "string",
        required: false,
        description: "Pytest pattern to run",
      },
    ],
  },
  {
    id: "js-sec-validate",
    name: "JavaScript Security Validation",
    description: "Run security validation for JavaScript/TypeScript code changes",
    language: "javascript",
    parameters: [
      {
        name: "test_pattern",
        type: "string",
        required: false,
        description: "Test pattern to run",
      },
    ],
  },
  {
    id: "generic-unit-test",
    name: "Generic Unit Test Runner",
    description: "Run unit tests in an isolated environment",
    language: "any",
    parameters: [
      {
        name: "command",
        type: "string",
        required: true,
        description: "Test command to execute",
      },
    ],
  },
];

export function getTemplate(templateId: string): JobTemplate | null {
  return ALLOWED_TEMPLATES.find((t) => t.id === templateId) ?? null;
}

export function isTemplateAllowed(templateId: string): boolean {
  return ALLOWED_TEMPLATES.some((t) => t.id === templateId);
}
