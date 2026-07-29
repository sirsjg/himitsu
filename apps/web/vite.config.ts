import { execFileSync } from "node:child_process";
import { defineConfig } from "vite";

// The release pipeline passes the tag and commit in as build arguments, because the
// container build context has no .git directory to describe. A local `npm run build`
// falls back to git, and anything else falls back to a literal so the footer and the
// /health/live stamp are never blank.
function fromGit(...args: readonly string[]): string | null {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
}

const version = process.env.HIMITSU_VERSION?.trim() || fromGit("describe", "--tags", "--always", "--dirty") || "dev";
const commit = process.env.HIMITSU_COMMIT?.trim() || fromGit("rev-parse", "--short=7", "HEAD") || "unknown";

export default defineConfig({
  define: {
    __HIMITSU_VERSION__: JSON.stringify(version),
    __HIMITSU_COMMIT__: JSON.stringify(commit),
  },
  build: { sourcemap: true },
  server: { port: 5173, strictPort: true },
});
