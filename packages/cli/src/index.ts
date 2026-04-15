import { createProgram } from "./program.js";

const program = createProgram();
program.parseAsync(process.argv).catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
