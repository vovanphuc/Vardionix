void (async () => {
  const { createDefaultProgram } = await import("./program.js");
  const program = await createDefaultProgram();
  await program.parseAsync(process.argv);
})().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
