import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";

export interface RepoConfig {
  readonly apiUrl: string;
  readonly projectId: string;
  readonly environmentId: string;
}

export interface StoredCredentials {
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly expiresAt: string;
  readonly activeOrgId: string;
}

interface SecretMetadata {
  readonly id: string;
  readonly key: string;
  readonly currentVersion: number;
}

interface LoginResult {
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly expiresAt: string;
  readonly activeOrgId: string | null;
  readonly organizations: readonly { readonly id: string; readonly name: string; readonly slug: string; readonly role: string; readonly active: boolean }[];
}

type RequestFunction = (input: string, init?: RequestInit) => Promise<Response>;

export class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}

export class HimitsuApiClient {
  readonly #baseUrl: string;
  readonly #request: RequestFunction;
  readonly #credential: StoredCredentials | null;
  readonly #token: string | null;

  constructor(options: {
    apiUrl: string;
    request?: RequestFunction;
    credential?: StoredCredentials | null;
    token?: string | null;
  }) {
    this.#baseUrl = normalizedApiUrl(options.apiUrl);
    this.#request = options.request ?? ((input, init) => fetch(input, init));
    this.#credential = options.credential ?? null;
    this.#token = options.token ?? null;
  }

  async login(email: string, password: string, orgId?: string): Promise<LoginResult> {
    return this.#json("/api/v1/cli/login", { method: "POST", body: JSON.stringify({ email, password, ...(orgId === undefined ? {} : { orgId }) }) }, false);
  }

  async listSecrets(projectId: string, environmentId: string): Promise<readonly SecretMetadata[]> {
    const all: SecretMetadata[] = [];
    let offset = 0;
    while (true) {
      const page = await this.#envelope<readonly SecretMetadata[]>(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets?limit=100&offset=${offset}`);
      all.push(...page.data);
      if (all.length >= (page.meta?.total ?? all.length)) return all;
      offset += page.data.length;
      if (page.data.length === 0) return all;
    }
  }

  async allSecrets(projectId: string, environmentId: string): Promise<Readonly<Record<string, string>>> {
    const metadata = await this.listSecrets(projectId, environmentId);
    if (metadata.length === 0) return {};
    const values: Record<string, string> = {};
    for (let offset = 0; offset < metadata.length; offset += 100) {
      Object.assign(values, await this.#json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets/bulk-get`, {
        method: "POST", body: JSON.stringify({ keys: metadata.slice(offset, offset + 100).map(({ key }) => key) }),
      }));
    }
    return values;
  }

  async push(projectId: string, environmentId: string, format: "dotenv" | "json", content: string, strategy: "skip" | "overwrite" | "merge", delimiter = "__"): Promise<unknown> {
    return this.#json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/imports/${format}`, {
      method: "POST", body: JSON.stringify({ content, strategy, ...(format === "json" ? { delimiter } : {}) }),
    });
  }

  async check(projectId: string): Promise<{ healthy: boolean; exitCode: 0 | 1; activeFindings: number; errors: number; warnings: number }> {
    const report = await this.#json<{ summary: { healthy: boolean; exitCode: 0 | 1; activeFindings: number; errors: number; warnings: number } }>(`/api/v1/projects/${encodeURIComponent(projectId)}/consistency`);
    return report.summary;
  }

  async getSecret(projectId: string, environmentId: string, key: string): Promise<{ id: string; key: string; value: string; currentVersion: number }> {
    const secret = (await this.listSecrets(projectId, environmentId)).find((candidate) => candidate.key === key);
    if (secret === undefined) throw new CliError(`Secret not found: ${key}`, 2);
    return this.#json(`/api/v1/secrets/${encodeURIComponent(secret.id)}`);
  }

  async setSecret(projectId: string, environmentId: string, key: string, value: string): Promise<void> {
    const existing = (await this.listSecrets(projectId, environmentId)).find((candidate) => candidate.key === key);
    if (existing === undefined) {
      await this.#json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets`, {
        method: "POST", body: JSON.stringify({ key, value }),
      });
      return;
    }
    await this.#json(`/api/v1/secrets/${encodeURIComponent(existing.id)}`, {
      method: "PATCH", headers: { "if-match": `"${existing.currentVersion}"` }, body: JSON.stringify({ value, changeNote: "Updated with himitsu CLI" }),
    });
  }

  async removeSecret(projectId: string, environmentId: string, key: string): Promise<void> {
    const secret = (await this.listSecrets(projectId, environmentId)).find((candidate) => candidate.key === key);
    if (secret === undefined) throw new CliError(`Secret not found: ${key}`, 2);
    await this.#json(`/api/v1/secrets/${encodeURIComponent(secret.id)}`, { method: "DELETE" });
  }

  async #envelope<T>(path: string, init?: RequestInit, authenticated = true): Promise<{ data: T; meta?: { total?: number } }> {
    const headers = new Headers({ accept: "application/json", ...init?.headers });
    if (init?.body !== undefined) headers.set("content-type", "application/json");
    if (authenticated) {
      if (this.#token !== null) headers.set("authorization", `Bearer ${this.#token}`);
      else if (this.#credential !== null) {
        headers.set("cookie", `__Host-himitsu_session=${encodeURIComponent(this.#credential.sessionToken)}`);
        if (!(["GET", "HEAD"] as const).includes((init?.method ?? "GET") as "GET" | "HEAD")) headers.set("x-csrf-token", this.#credential.csrfToken);
      } else throw new CliError("Not authenticated. Run `himitsu login` or set HIMITSU_TOKEN.", 3);
    }
    const response = await this.#request(`${this.#baseUrl}${path}`, { ...init, headers });
    const payload = await response.json().catch(() => null) as { data?: T; meta?: { total?: number }; error?: { message?: string } } | null;
    if (!response.ok || payload?.data === undefined) throw new CliError(payload?.error?.message ?? `API request failed (${response.status})`, response.status === 401 || response.status === 403 ? 3 : 1);
    return { data: payload.data, ...(payload.meta === undefined ? {} : { meta: payload.meta }) };
  }

  async #json<T>(path: string, init?: RequestInit, authenticated = true): Promise<T> {
    return (await this.#envelope<T>(path, init, authenticated)).data;
  }
}

export function serializeDotenv(secrets: Readonly<Record<string, string>>): string {
  return Object.entries(secrets).sort(([left], [right]) => left.localeCompare(right)).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join("\n") + (Object.keys(secrets).length === 0 ? "" : "\n");
}

export function serializeJson(secrets: Readonly<Record<string, string>>): string {
  return JSON.stringify(Object.fromEntries(Object.entries(secrets).sort(([left], [right]) => left.localeCompare(right))), null, 2) + "\n";
}

export async function findRepoConfig(startDirectory = process.cwd()): Promise<{ path: string; config: RepoConfig }> {
  let directory = resolve(startDirectory);
  while (true) {
    const path = join(directory, ".himitsu.json");
    try {
      await access(path, constants.R_OK);
      return { path, config: parseRepoConfig(JSON.parse(await readFile(path, "utf8")) as unknown) };
    } catch (error) {
      if ((error as { code?: string }).code !== "ENOENT") throw error;
    }
    const parent = dirname(directory);
    if (parent === directory) throw new CliError("No .himitsu.json found. Run `himitsu config set --project … --environment …`.", 2);
    directory = parent;
  }
}

export async function writeRepoConfig(directory: string, config: RepoConfig): Promise<string> {
  const normalized = parseRepoConfig(config);
  const path = join(resolve(directory), ".himitsu.json");
  await writeFile(path, JSON.stringify(normalized, null, 2) + "\n", { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

export function credentialFilePath(environment: NodeJS.ProcessEnv = process.env): string {
  const root = environment.HIMITSU_CONFIG_HOME?.trim() || join(homedir(), ".config", "himitsu");
  return join(root, "credentials.json");
}

export async function readCredentials(environment: NodeJS.ProcessEnv = process.env): Promise<StoredCredentials | null> {
  try {
    const value = JSON.parse(await readFile(credentialFilePath(environment), "utf8")) as StoredCredentials;
    if (!value.sessionToken || !value.csrfToken || !value.activeOrgId || !Number.isFinite(new Date(value.expiresAt).getTime())) throw new Error("invalid");
    return value;
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") return null;
    throw new CliError("Stored Himitsu credentials are invalid. Run `himitsu login` again.", 3);
  }
}

export async function writeCredentials(credentials: StoredCredentials, environment: NodeJS.ProcessEnv = process.env): Promise<string> {
  const path = credentialFilePath(environment);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await writeFile(path, JSON.stringify(credentials, null, 2) + "\n", { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

interface ParsedArguments { readonly positionals: readonly string[]; readonly options: Readonly<Record<string, string | boolean>>; readonly passthrough: readonly string[] }

export function parseArguments(arguments_: readonly string[]): ParsedArguments {
  const separator = arguments_.indexOf("--");
  const source = separator < 0 ? arguments_ : arguments_.slice(0, separator);
  const passthrough = separator < 0 ? [] : arguments_.slice(separator + 1);
  const positionals: string[] = [];
  const options: Record<string, string | boolean> = {};
  for (let index = 0; index < source.length; index += 1) {
    const argument = source[index] ?? "";
    if (!argument.startsWith("--")) { positionals.push(argument); continue; }
    const equal = argument.indexOf("=");
    if (equal > 2) { options[argument.slice(2, equal)] = argument.slice(equal + 1); continue; }
    const name = argument.slice(2);
    const next = source[index + 1];
    if (next !== undefined && !next.startsWith("--")) { options[name] = next; index += 1; }
    else options[name] = true;
  }
  return { positionals, options, passthrough };
}

interface MainOptions {
  readonly cwd?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly stdin?: Readable;
  readonly stdout?: Writable;
  readonly stderr?: Writable;
  readonly request?: RequestFunction;
  readonly spawnProcess?: typeof spawn;
}

export async function main(argv: readonly string[], options: MainOptions = {}): Promise<number> {
  const cwd = options.cwd ?? process.cwd();
  const environment = options.environment ?? process.env;
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  try {
    const parsed = parseArguments(argv);
    const [command, subcommand, ...rest] = parsed.positionals;
    if (command === undefined || command === "help" || parsed.options.help === true) { stdout.write(helpText); return 0; }
    if (command === "config" && subcommand === "set") {
      const projectId = stringOption(parsed, "project");
      const environmentId = stringOption(parsed, "environment");
      const apiUrl = optionalString(parsed, "api-url") ?? "http://localhost:3000";
      const path = await writeRepoConfig(cwd, { apiUrl, projectId, environmentId });
      stdout.write(`Wrote ${path}\n`); return 0;
    }
    const repo = await findRepoConfig(cwd);
    if (command === "login") {
      const email = optionalString(parsed, "email") ?? environment.HIMITSU_EMAIL;
      if (email === undefined) throw new CliError("Login requires --email or HIMITSU_EMAIL.", 2);
      const password = parsed.options["password-stdin"] === true ? await readOneLine(stdin) : await promptHidden(stdin, stdout, "Password: ");
      const unauthenticated = new HimitsuApiClient({ apiUrl: optionalString(parsed, "api-url") ?? repo.config.apiUrl, ...(options.request === undefined ? {} : { request: options.request }) });
      const result = await unauthenticated.login(email, password, optionalString(parsed, "org"));
      if (result.activeOrgId === null) throw new CliError(`Multiple organizations available; rerun with --org <id>.\n${result.organizations.map(({ id, name }) => `${id}  ${name}`).join("\n")}`, 2);
      await writeCredentials({ sessionToken: result.sessionToken, csrfToken: result.csrfToken, expiresAt: result.expiresAt, activeOrgId: result.activeOrgId }, environment);
      stdout.write(`Logged in to ${result.organizations.find(({ active }) => active)?.name ?? result.activeOrgId}.\n`); return 0;
    }
    const credential = environment.HIMITSU_TOKEN === undefined ? await readCredentials(environment) : null;
    const client = new HimitsuApiClient({ apiUrl: repo.config.apiUrl, ...(options.request === undefined ? {} : { request: options.request }), credential, token: environment.HIMITSU_TOKEN ?? null });
    if (command === "pull") {
      const format = formatOption(parsed, optionalString(parsed, "format") ?? "dotenv");
      const content = format === "json" ? serializeJson(await client.allSecrets(repo.config.projectId, repo.config.environmentId)) : serializeDotenv(await client.allSecrets(repo.config.projectId, repo.config.environmentId));
      const output = optionalString(parsed, "out") ?? "-";
      if (output === "-") stdout.write(content); else { await writeFile(resolve(cwd, output), content, { mode: 0o600 }); await chmod(resolve(cwd, output), 0o600); stdout.write(`Wrote ${output}\n`); }
      return 0;
    }
    if (command === "push") {
      const file = subcommand;
      if (file === undefined) throw new CliError("Usage: himitsu push <file> [--format dotenv|json]", 2);
      const format = formatOption(parsed, optionalString(parsed, "format") ?? (extname(file).toLowerCase() === ".json" ? "json" : "dotenv"));
      const strategy = strategyOption(parsed);
      await client.push(repo.config.projectId, repo.config.environmentId, format, await readFile(resolve(cwd, file), "utf8"), strategy, optionalString(parsed, "delimiter") ?? "__");
      stdout.write(`Imported ${file}.\n`); return 0;
    }
    if (command === "check") {
      const summary = await client.check(repo.config.projectId);
      stdout.write(`${summary.healthy ? "healthy" : "drift"}: ${summary.errors} errors, ${summary.warnings} warnings (${summary.activeFindings} active)\n`);
      return summary.exitCode;
    }
    if (command === "run") {
      const child = parsed.passthrough;
      if (child.length === 0) throw new CliError("Usage: himitsu run -- <command> [args...]", 2);
      const secrets = await client.allSecrets(repo.config.projectId, repo.config.environmentId);
      return await runChild(options.spawnProcess ?? spawn, child[0] ?? "", child.slice(1), { ...environment, ...secrets });
    }
    if (command === "secrets" && subcommand === "get") {
      const key = rest[0]; if (key === undefined) throw new CliError("Usage: himitsu secrets get <KEY>", 2);
      stdout.write(`${(await client.getSecret(repo.config.projectId, repo.config.environmentId, key)).value}\n`); return 0;
    }
    if (command === "secrets" && subcommand === "set") {
      const key = rest[0]; if (key === undefined) throw new CliError("Usage: himitsu secrets set <KEY> --value-stdin", 2);
      const value = parsed.options["value-stdin"] === true ? await readOneLine(stdin) : await promptHidden(stdin, stdout, "Secret value: ");
      await client.setSecret(repo.config.projectId, repo.config.environmentId, key, value); stdout.write(`Set ${key}.\n`); return 0;
    }
    if (command === "secrets" && (subcommand === "rm" || subcommand === "remove")) {
      const key = rest[0]; if (key === undefined) throw new CliError("Usage: himitsu secrets rm <KEY>", 2);
      await client.removeSecret(repo.config.projectId, repo.config.environmentId, key); stdout.write(`Removed ${key}.\n`); return 0;
    }
    throw new CliError(`Unknown command: ${[command, subcommand].filter(Boolean).join(" ")}`, 2);
  } catch (error) {
    const failure = error instanceof CliError ? error : new CliError(error instanceof Error ? error.message : "Unexpected CLI failure");
    stderr.write(`himitsu: ${failure.message}\n`);
    return failure.exitCode;
  }
}

function parseRepoConfig(value: unknown): RepoConfig {
  if (typeof value !== "object" || value === null) throw new CliError(".himitsu.json must contain an object.", 2);
  const config = value as Partial<RepoConfig>;
  if (typeof config.apiUrl !== "string" || typeof config.projectId !== "string" || typeof config.environmentId !== "string") throw new CliError(".himitsu.json requires apiUrl, projectId, and environmentId.", 2);
  return { apiUrl: normalizedApiUrl(config.apiUrl), projectId: requiredIdentifier(config.projectId, "projectId"), environmentId: requiredIdentifier(config.environmentId, "environmentId") };
}

function normalizedApiUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new CliError("API URL must use http or https.", 2);
  return url.toString().replace(/\/$/, "");
}

function requiredIdentifier(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized === "" || normalized.length > 255 || /\s/.test(normalized)) throw new CliError(`${name} is invalid.`, 2);
  return normalized;
}

function stringOption(parsed: ParsedArguments, name: string): string {
  const value = optionalString(parsed, name);
  if (value === undefined) throw new CliError(`Missing --${name}.`, 2);
  return value;
}

function optionalString(parsed: ParsedArguments, name: string): string | undefined {
  const value = parsed.options[name];
  return typeof value === "string" && value !== "" ? value : undefined;
}

function formatOption(_parsed: ParsedArguments, value: string): "dotenv" | "json" {
  if (value !== "dotenv" && value !== "json") throw new CliError("Format must be dotenv or json.", 2);
  return value;
}

function strategyOption(parsed: ParsedArguments): "skip" | "overwrite" | "merge" {
  const value = optionalString(parsed, "strategy") ?? "skip";
  if (value !== "skip" && value !== "overwrite" && value !== "merge") throw new CliError("Strategy must be skip, overwrite, or merge.", 2);
  return value;
}

async function readOneLine(input: Readable): Promise<string> {
  const reader = createInterface({ input });
  try { return (await reader.question("")).replace(/\r?\n$/, ""); }
  finally { reader.close(); }
}

async function promptHidden(input: Readable, output: Writable, prompt: string): Promise<string> {
  const terminal = input as Readable & { isTTY?: boolean; setRawMode?: (enabled: boolean) => void };
  if (terminal.isTTY !== true || terminal.setRawMode === undefined) throw new CliError("Use --password-stdin/--value-stdin when input is not an interactive terminal.", 2);
  output.write(prompt); terminal.setRawMode(true); input.resume();
  return new Promise((resolvePassword, reject) => {
    let value = "";
    const cleanup = () => { terminal.setRawMode?.(false); input.pause(); input.off("data", onData); input.off("error", onError); output.write("\n"); };
    const finish = () => { cleanup(); resolvePassword(value); };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onData = (chunk: Buffer | string) => {
      const text = chunk.toString();
      for (const character of text) {
        if (character === "\r" || character === "\n") { finish(); return; }
        if (character === "\u0003") { cleanup(); reject(new CliError("Canceled.", 130)); return; }
        if (character === "\u007f") value = value.slice(0, -1);
        else value += character;
      }
    };
    input.on("data", onData);
    input.once("error", onError);
  });
}

export async function runChild(spawnProcess: typeof spawn, command: string, arguments_: readonly string[], environment: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolveExit, reject) => {
    const child = spawnProcess(command, [...arguments_], { env: environment, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => resolveExit(code ?? (signal === null ? 1 : 128)));
  });
}

const helpText = `himitsu — encrypted configuration from the command line

Usage:
  himitsu config set --project ID --environment ID [--api-url URL]
  himitsu login --email EMAIL [--org ID] [--password-stdin]
  himitsu pull [--format dotenv|json] [--out FILE|-]
  himitsu push FILE [--format dotenv|json] [--strategy skip|overwrite|merge]
  himitsu run -- <command> [args...]
  himitsu check
  himitsu secrets set KEY [--value-stdin]
  himitsu secrets get KEY
  himitsu secrets rm KEY

Set HIMITSU_TOKEN to use a service token without stored session credentials.
`;
