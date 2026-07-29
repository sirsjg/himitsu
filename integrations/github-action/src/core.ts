/**
 * A zero-dependency subset of @actions/core.
 *
 * The action ships its compiled output straight to the runner, so avoiding
 * dependencies means there is no vendored node_modules tree to audit or keep
 * patched — which matters more than usual for something that handles secrets.
 */
import { appendFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { EOL } from "node:os";

export interface Runtime {
  readonly env: NodeJS.ProcessEnv;
  /** Writes a line to the workflow log. */
  readonly log: (line: string) => void;
  /** Appends to one of the runner's command files (GITHUB_ENV, GITHUB_OUTPUT). */
  readonly appendCommandFile: (path: string, content: string) => Promise<void>;
}

export const defaultRuntime: Runtime = {
  env: process.env,
  log: (line) => process.stdout.write(line + EOL),
  appendCommandFile: (path, content) => appendFile(path, content, { encoding: "utf8" }),
};

/**
 * Escapes a value for a `::workflow-command::` line. Without this a value
 * containing a newline would terminate the command early and the remainder
 * would be echoed to the log verbatim — the exact leak masking exists to stop.
 */
function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

export class ActionCore {
  readonly #runtime: Runtime;

  constructor(runtime: Runtime = defaultRuntime) {
    this.#runtime = runtime;
  }

  get env(): NodeJS.ProcessEnv {
    return this.#runtime.env;
  }

  /**
   * Reads an action input. GitHub exposes `foo-bar` as `INPUT_FOO-BAR`, upper
   * cased with spaces replaced by underscores.
   */
  input(name: string, options: { required?: boolean; default?: string } = {}): string {
    const key = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
    const raw = this.#runtime.env[key];
    const value = (raw ?? "").trim();
    if (value === "") {
      if (options.default !== undefined) return options.default;
      if (options.required === true) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      return "";
    }
    return value;
  }

  booleanInput(name: string, fallback: boolean): boolean {
    const value = this.input(name).toLowerCase();
    if (value === "") return fallback;
    if (["true", "yes", "1", "on"].includes(value)) return true;
    if (["false", "no", "0", "off"].includes(value)) return false;
    throw new Error(`Input ${name} must be a boolean, got ${JSON.stringify(value)}`);
  }

  /** Splits a comma or newline separated list input. */
  listInput(name: string): readonly string[] {
    return this.input(name)
      .split(/[\n,]/)
      .map((entry) => entry.trim())
      .filter((entry) => entry !== "");
  }

  info(message: string): void {
    this.#runtime.log(message);
  }

  warning(message: string): void {
    this.#runtime.log(`::warning::${escapeData(message)}`);
  }

  debug(message: string): void {
    this.#runtime.log(`::debug::${escapeData(message)}`);
  }

  error(message: string): void {
    this.#runtime.log(`::error::${escapeData(message)}`);
  }

  /**
   * Registers a value for redaction in all subsequent log output.
   *
   * Empty and whitespace-only values are skipped: masking "" would make the
   * runner replace every empty string in the log with ***, which destroys
   * readability without protecting anything.
   */
  mask(value: string): void {
    if (value.trim() === "") return;
    this.#runtime.log(`::add-mask::${escapeData(value)}`);
  }

  /** Sets an action output via the GITHUB_OUTPUT command file. */
  async setOutput(name: string, value: string): Promise<void> {
    await this.#writeKeyValue("GITHUB_OUTPUT", name, value);
  }

  /** Exports an environment variable to subsequent workflow steps. */
  async exportVariable(name: string, value: string): Promise<void> {
    await this.#writeKeyValue("GITHUB_ENV", name, value);
  }

  /**
   * Writes a name/value pair in the runner's heredoc format, which is the only
   * form that survives multi-line values.
   */
  async #writeKeyValue(fileVariable: string, name: string, value: string): Promise<void> {
    const path = this.#runtime.env[fileVariable];
    if (path === undefined || path === "") {
      throw new Error(
        `${fileVariable} is not set. This action must run on a GitHub Actions runner.`,
      );
    }
    const delimiter = `ghadelimiter_${randomBytes(16).toString("hex")}`;
    // A value containing the delimiter could inject arbitrary variables. The
    // delimiter is random per write, so this is effectively unreachable — but
    // failing closed is the only safe response if it ever happens.
    if (value.includes(delimiter) || name.includes(delimiter)) {
      throw new Error(`Refusing to write ${name}: value collides with the generated delimiter`);
    }
    if (name.includes("\n") || name.includes("\r")) {
      throw new Error(`Refusing to write an environment name containing a newline: ${JSON.stringify(name)}`);
    }
    await this.#runtime.appendCommandFile(path, `${name}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`);
  }
}
