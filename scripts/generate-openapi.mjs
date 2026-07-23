import { writeFile } from "node:fs/promises";
import { buildApi } from "../apps/api/dist/src/index.js";

const output = new URL("../docs/openapi.json", import.meta.url);
const app = await buildApi({});
try {
  await writeFile(output, `${JSON.stringify(app.swagger(), null, 2)}\n`, "utf8");
  process.stdout.write("Generated docs/openapi.json from the registered API routes.\n");
} finally {
  await app.close();
}
