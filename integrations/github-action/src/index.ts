import { ActionCore } from "./core.js";
import { run } from "./run.js";

const core = new ActionCore();

try {
  await run({ core });
} catch (error) {
  // Only the message is emitted. A stack trace can contain interpolated
  // request URLs and argument values, which is not worth the diagnostic gain
  // in a step that handles secrets.
  core.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
