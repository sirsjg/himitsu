import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import type { spawn } from "node:child_process";
import {
  HimitsuApiClient,
  credentialFilePath,
  findRepoConfig,
  main,
  parseArguments,
  readCredentials,
  serializeDotenv,
  serializeJson,
  writeCredentials,
  writeRepoConfig,
} from "../src/index.js";

class Capture extends Writable {
  value = "";
  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.value += chunk.toString();
    callback();
  }
}

function jsonResponse(data: unknown, status = 200, meta?: unknown): Response {
  return new Response(JSON.stringify({ ...(status < 400 ? { data } : { error: data }), ...(meta === undefined ? {} : { meta }) }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("parses options and serializes stable dotenv and JSON output", () => {
  assert.deepEqual(parseArguments(["run", "--verbose", "--name=value", "--", "node", "app.js"]), {
    positionals: ["run"], options: { verbose: true, name: "value" }, passthrough: ["node", "app.js"],
  });
  assert.equal(serializeDotenv({ ZED: "line\nvalue", ALPHA: "quoted value" }), "ALPHA=\"quoted value\"\nZED=\"line\\nvalue\"\n");
  assert.equal(serializeJson({ ZED: "last", ALPHA: "first" }), '{\n  "ALPHA": "first",\n  "ZED": "last"\n}\n');
});

test("writes private repository configuration and discovers it from descendants", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-config-"));
  try {
    const nested = join(root, "packages", "api");
    await mkdir(nested, { recursive: true });
    const path = await writeRepoConfig(root, { apiUrl: "https://example.test/", projectId: "project-a", environmentId: "env-b" });
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual(await findRepoConfig(nested), {
      path,
      config: { apiUrl: "https://example.test", projectId: "project-a", environmentId: "env-b" },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stores session credentials in a private per-user configuration file", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-creds-"));
  const environment = { HIMITSU_CONFIG_HOME: root };
  const credentials = { sessionToken: "session", csrfToken: "csrf", expiresAt: "2030-01-01T00:00:00.000Z", activeOrgId: "org-a" };
  try {
    assert.equal(credentialFilePath(environment), join(root, "credentials.json"));
    await writeCredentials(credentials, environment);
    assert.deepEqual(await readCredentials(environment), credentials);
    assert.equal((await stat(root)).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, "credentials.json"))).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("API client paginates metadata, batches values, and uses bearer authentication", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const metadata = Array.from({ length: 101 }, (_, index) => ({ id: `secret-${index}`, key: `KEY_${index}`, currentVersion: 1 }));
  const request = async (url: string, init?: RequestInit): Promise<Response> => {
    calls.push({ url, ...(init === undefined ? {} : { init }) });
    if (url.includes("offset=0")) return jsonResponse(metadata.slice(0, 100), 200, { total: 101 });
    if (url.includes("offset=100")) return jsonResponse(metadata.slice(100), 200, { total: 101 });
    const keys = (JSON.parse(String(init?.body)) as { keys: string[] }).keys;
    return jsonResponse(Object.fromEntries(keys.map((key) => [key, `value-${key}`])));
  };
  const result = await new HimitsuApiClient({ apiUrl: "https://api.test", token: "service-token", request }).allSecrets("project", "environment");
  assert.equal(Object.keys(result).length, 101);
  assert.equal(result.KEY_100, "value-KEY_100");
  assert.equal(calls.filter(({ url }) => url.endsWith("bulk-get")).length, 2);
  for (const call of calls) assert.equal(new Headers(call.init?.headers).get("authorization"), "Bearer service-token");
});

test("API client supports push, get, create, update, and remove operations", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  let listCount = 0;
  const request = async (url: string, init?: RequestInit): Promise<Response> => {
    calls.push({ url, ...(init === undefined ? {} : { init }) });
    if (url.includes("/secrets?")) {
      listCount += 1;
      return jsonResponse(listCount === 2 ? [] : [{ id: "secret-a", key: "EXISTING", currentVersion: 4 }], 200, { total: listCount === 2 ? 0 : 1 });
    }
    if (url.includes("/exports?")) return jsonResponse({ format: "shell", filename: "project-environment.sh", mimeType: "text/plain", content: "export A='b'\n", secretCount: 1, nested: false });
    if (url.endsWith("/secret-a") && (init?.method ?? "GET") === "GET") return jsonResponse({ id: "secret-a", key: "EXISTING", value: "secret-value", currentVersion: 4 });
    return jsonResponse({ ok: true });
  };
  const client = new HimitsuApiClient({ apiUrl: "https://api.test", credential: { sessionToken: "session", csrfToken: "csrf", expiresAt: "2030-01-01T00:00:00.000Z", activeOrgId: "org" }, request });
  assert.equal((await client.getSecret("project", "environment", "EXISTING")).value, "secret-value");
  await client.setSecret("project", "environment", "NEW", "new-value");
  await client.setSecret("project", "environment", "EXISTING", "updated");
  await client.removeSecret("project", "environment", "EXISTING");
  await client.push("project", "environment", "json", '{"A":"b"}', "merge", ".");
  assert.equal((await client.exportConfig("project", "environment", "shell")).content, "export A='b'\n");
  const patch = calls.find(({ init }) => init?.method === "PATCH");
  assert.equal(new Headers(patch?.init?.headers).get("if-match"), '"4"');
  assert.equal(new Headers(patch?.init?.headers).get("x-csrf-token"), "csrf");
  assert.ok(calls.some(({ url, init }) => url.endsWith("/secrets") && init?.method === "POST"));
  assert.ok(calls.some(({ url, init }) => url.endsWith("/secret-a") && init?.method === "DELETE"));
  assert.ok(calls.some(({ url }) => url.endsWith("/imports/json")));
  assert.ok(calls.some(({ url }) => url.endsWith("/exports?format=shell")));
});

test("login reads a password from stdin and persists the selected organization session", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-login-"));
  const configHome = join(root, "credentials");
  const stdout = new Capture();
  const stderr = new Capture();
  try {
    await writeRepoConfig(root, { apiUrl: "https://api.test", projectId: "project", environmentId: "environment" });
    const request = async (_url: string, init?: RequestInit): Promise<Response> => {
      assert.deepEqual(JSON.parse(String(init?.body)), { email: "user@example.test", password: "password" });
      return jsonResponse({ sessionToken: "session", csrfToken: "csrf", expiresAt: "2030-01-01T00:00:00.000Z", activeOrgId: "org", organizations: [{ id: "org", name: "Team", slug: "team", role: "admin", active: true }] });
    };
    assert.equal(await main(["login", "--email", "user@example.test", "--password-stdin"], { cwd: root, environment: { HIMITSU_CONFIG_HOME: configHome }, stdin: Readable.from("password\n"), stdout, stderr, request }), 0);
    assert.equal(stderr.value, "");
    assert.match(stdout.value, /Logged in to Team/);
    assert.equal((await readCredentials({ HIMITSU_CONFIG_HOME: configHome }))?.sessionToken, "session");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("pull writes a private file and check returns the consistency exit code", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-pull-"));
  try {
    await writeRepoConfig(root, { apiUrl: "https://api.test", projectId: "project", environmentId: "environment" });
    const requested: string[] = [];
    const request = async (url: string): Promise<Response> => {
      requested.push(url);
      if (url.includes("/consistency")) return jsonResponse({ summary: { healthy: false, exitCode: 1, activeFindings: 2, errors: 1, warnings: 1 } });
      if (url.includes("/exports?")) return jsonResponse({ format: "json", filename: "project-environment.json", mimeType: "application/json", content: '{\n  "API_KEY": "value"\n}\n', secretCount: 1, nested: true });
      throw new Error(`Unexpected request: ${url}`);
    };
    const environment = { HIMITSU_TOKEN: "token" };
    assert.equal(await main(["pull", "--format", "json", "--nested", "--out", "secrets.json"], { cwd: root, environment, stdout: new Capture(), stderr: new Capture(), request }), 0);
    assert.equal(await readFile(join(root, "secrets.json"), "utf8"), '{\n  "API_KEY": "value"\n}\n');
    assert.equal((await stat(join(root, "secrets.json"))).mode & 0o777, 0o600);
    assert.match(requested[0] ?? "", /\/exports\?format=json&nested=true&delimiter=__/);
    const stdout = new Capture();
    assert.equal(await main(["check"], { cwd: root, environment, stdout, stderr: new Capture(), request }), 1);
    assert.match(stdout.value, /^drift: 1 errors, 1 warnings/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("run injects fetched secrets into a child process without writing them to disk", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-run-"));
  const calls: unknown[][] = [];
  try {
    await writeRepoConfig(root, { apiUrl: "https://api.test", projectId: "project", environmentId: "environment" });
    const request = async (url: string): Promise<Response> => url.includes("/secrets?")
      ? jsonResponse([{ id: "secret", key: "INJECTED_SECRET", currentVersion: 1 }], 200, { total: 1 })
      : jsonResponse({ INJECTED_SECRET: "runtime-value" });
    const spawnProcess = ((...arguments_: unknown[]) => {
      calls.push(arguments_);
      const child = new EventEmitter();
      queueMicrotask(() => child.emit("exit", 7, null));
      return child;
    }) as unknown as typeof spawn;
    const environment = { HIMITSU_TOKEN: "token", EXISTING: "kept" };
    assert.equal(await main(["run", "--", "program", "arg"], { cwd: root, environment, stdout: new Capture(), stderr: new Capture(), request, spawnProcess }), 7);
    assert.equal(calls[0]?.[0], "program");
    assert.deepEqual(calls[0]?.[1], ["arg"]);
    const spawnOptions = calls[0]?.[2] as { env: Record<string, string>; stdio: string };
    assert.equal(spawnOptions.env.INJECTED_SECRET, "runtime-value");
    assert.equal(spawnOptions.env.EXISTING, "kept");
    assert.equal(spawnOptions.stdio, "inherit");
    assert.deepEqual((await readFile(join(root, ".himitsu.json"), "utf8")).includes("runtime-value"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("push sends an on-disk dotenv file through the import API", async () => {
  const root = await mkdtemp(join(tmpdir(), "himitsu-cli-push-"));
  try {
    await writeRepoConfig(root, { apiUrl: "https://api.test", projectId: "project", environmentId: "environment" });
    await writeFile(join(root, ".env.local"), "API_KEY=value\n");
    let requestBody = "";
    const request = async (_url: string, init?: RequestInit): Promise<Response> => { requestBody = String(init?.body); return jsonResponse({ created: 1 }); };
    assert.equal(await main(["push", ".env.local", "--strategy", "overwrite"], { cwd: root, environment: { HIMITSU_TOKEN: "token" }, stdout: new Capture(), stderr: new Capture(), request }), 0);
    assert.deepEqual(JSON.parse(requestBody), { content: "API_KEY=value\n", strategy: "overwrite" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
