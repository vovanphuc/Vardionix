const assert = require("node:assert/strict");

async function run() {
  const vscode = require("vscode");

  const extension = vscode.extensions.getExtension("vardionix.vardionix-vscode");
  assert.ok(extension, "Extension should be available in the VS Code host");

  await extension.activate();

  const commands = await vscode.commands.getCommands(true);
  assert.ok(commands.includes("vardionix.refreshFindings"));
  assert.ok(commands.includes("vardionix.listExcludedFindings"));

  await vscode.commands.executeCommand("vardionix.refreshFindings");
}

module.exports = {
  run,
};
