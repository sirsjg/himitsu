import assert from "node:assert/strict";
import test from "node:test";

import { ActionCore, type Runtime } from "../src/core.js";
import { HimitsuClient, HimitsuError } from "../src/himitsu.js";
import { run, selectSecrets } from "../src/run.js";

const TOKEN = "himi_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

interface Harness {
  readonly core: ActionCore;
  readonly logs: string[];
  readonly files: Map<string, string>;
  readonly written: Map<string, string>;
}

function harness(inputs: Record<string, string>): Harness {
  const logs: string[] = [];
  const files = new Map<string, string>([
    ["/tmp/github_env", ""],
    ["/tmp/github_output", ""],
  ]);
  const env: NodeJS.ProcessEnv = {
    GITHUB_ENV: "/tmp/github_env",
    GITHUB_OUTPUT: "/tmp/github_output",
  };
  for (const [name, value] of Object.entries(inputs)) {
    env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] = value;
  }
  const runtime: Runtime = {
    env,
    log: (line) => logs.push(line),
    appendCommandFile: async (path, content) => {
      files.set(path, (files.get(path) ?? "") + content);
    },
  };
  return { core: new ActionCore(runtime), logs, files, written: new Map() };
}

/** Parses the runner's heredoc command-file format back into a map. */
function parseCommandFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const header = /^([^<]+)<<(ghadelimiter_[0-9a-f]{32})$/.exec(lines[index] ?? "");
    if (header === null) continue;
    const [, name, delimiter] = header;
    const value: string[] = [];
    index += 1;
    while (index < lines.length && lines[index] !== delimiter) {
      value.push(lines[index] ?? "");
      index += 1;
    }
    result[name as string] = value.join("\n");
  }
  return result;
}

function stubFetch(payload: unknown, status = 200): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

const runtimePayload = {
  data: { configVersion: 12, secrets: { DATABASE_URL: "postgres://u:p@h/db", API_KEY: "sk-live-1" } },
};

test("exports secrets to the environment", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.DATABASE_URL, "postgres://u:p@h/db");
  assert.equal(exported.API_KEY, "sk-live-1");

  const outputs = parseCommandFile(h.files.get("/tmp/github_output") ?? "");
  assert.equal(outputs["secret-count"], "2");
  assert.equal(outputs["config-version"], "12");
  assert.equal(outputs.keys, "API_KEY,DATABASE_URL");
});

test("masks every value and the token before exporting", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  const masked = h.logs.filter((line) => line.startsWith("::add-mask::"));
  for (const secret of [TOKEN, "postgres://u:p@h/db", "sk-live-1"]) {
    assert.ok(
      masked.some((line) => line === `::add-mask::${secret}`),
      `${secret} was never masked`,
    );
  }
});

test("masks before writing, so a later failure cannot leak an unmasked value", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  const firstMask = h.logs.findIndex((line) => line.startsWith("::add-mask::sk-live-1"));
  const firstInfo = h.logs.findIndex((line) => line.startsWith("Exported "));
  assert.ok(firstMask >= 0 && firstMask < firstInfo, "value was logged about before being masked");
});

test("mask: false skips redaction", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    mask: "false",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });
  assert.equal(h.logs.filter((line) => line.startsWith("::add-mask::")).length, 0);
});

test("multi-line values round-trip through the heredoc format", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  const key = "-----BEGIN KEY-----\nline2\nline3\n-----END KEY-----";
  await run({
    core: h.core,
    fetch: stubFetch({ data: { configVersion: 1, secrets: { PRIVATE_KEY: key } } }),
  });

  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.PRIVATE_KEY, key);
});

test("a value that mimics the command-file format cannot inject a variable", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  // A classic injection attempt: terminate the heredoc early and start a new
  // assignment. The random per-write delimiter makes it inert.
  const hostile = "safe\nghadelimiter_00000000000000000000000000000000\nINJECTED=pwned";
  await run({
    core: h.core,
    fetch: stubFetch({ data: { configVersion: 1, secrets: { NORMAL: hostile } } }),
  });

  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.NORMAL, hostile);
  assert.equal(exported.INJECTED, undefined);
});

test("a value containing a newline cannot break out of an ::add-mask:: command", () => {
  const h = harness({});
  h.core.mask("first\nsecond");
  assert.equal(h.logs[0], "::add-mask::first%0Asecond");
  assert.equal(h.logs.length, 1);
});

test("empty values are not masked", () => {
  const h = harness({});
  h.core.mask("");
  h.core.mask("   ");
  assert.equal(h.logs.length, 0);
});

test("keys that are not valid environment names are skipped with a warning", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
  });
  await run({
    core: h.core,
    fetch: stubFetch({
      data: {
        configVersion: 1,
        secrets: { GOOD: "good-value", "bad-key": "leaky-value", "9leading": "other-value" },
      },
    }),
  });

  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.GOOD, "good-value");
  assert.equal(exported["bad-key"], undefined);

  const warning = h.logs.find((line) => line.startsWith("::warning::"));
  assert.ok(warning?.includes("bad-key"), "warning should name the skipped key");
  assert.ok(warning?.includes("9leading"), "warning should name every skipped key");
  // The warning must name keys but never their values.
  assert.ok(!warning?.includes("leaky-value"), "warning leaked a secret value");
});

test("prefix is applied and validated", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    prefix: "APP_",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });
  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.APP_API_KEY, "sk-live-1");

  const bad = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    prefix: "bad prefix!",
  });
  await assert.rejects(
    () => run({ core: bad.core, fetch: stubFetch(runtimePayload) }),
    /prefix must be a valid environment variable prefix/,
  );
});

test("include acts as an allowlist and exclude as a denylist", () => {
  const secrets = { A: "1", B: "2", C: "3" };
  assert.deepEqual(selectSecrets(secrets, new Set(["A", "C"]), new Set()), { A: "1", C: "3" });
  assert.deepEqual(selectSecrets(secrets, new Set(), new Set(["B"])), { A: "1", C: "3" });
  // exclude wins over include for the same key.
  assert.deepEqual(selectSecrets(secrets, new Set(["A", "B"]), new Set(["B"])), { A: "1" });
  assert.deepEqual(selectSecrets(secrets, new Set(), new Set()), secrets);
});

test("include and exclude inputs filter the export", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    exclude: "API_KEY",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  const exported = parseCommandFile(h.files.get("/tmp/github_env") ?? "");
  assert.equal(exported.DATABASE_URL, "postgres://u:p@h/db");
  assert.equal(exported.API_KEY, undefined);
  // An excluded secret must not be masked either — masking it would confirm
  // its value was fetched, and needlessly redact unrelated log text.
  assert.ok(!h.logs.includes("::add-mask::sk-live-1"));
});

test("export-to: file writes with 0600 and warns about the plaintext", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "file",
    file: ".env",
    format: "dotenv",
  });
  await run({
    core: h.core,
    fetch: stubFetch({
      data: { format: "dotenv", filename: ".env", content: "A=\"1\"\nB=\"2\"\n", secretCount: 2 },
    }),
    writeSecretFile: async (path, content) => {
      h.written.set(path, content);
    },
  });

  const entries = [...h.written.entries()];
  assert.equal(entries.length, 1);
  const [path, content] = entries[0] as [string, string];
  assert.ok(path.endsWith("/.env"), `expected an absolute path, got ${path}`);
  assert.equal(content, "A=\"1\"\nB=\"2\"\n");
  assert.ok(h.logs.some((line) => line.startsWith("::warning::") && line.includes("plaintext")));

  const outputs = parseCommandFile(h.files.get("/tmp/github_output") ?? "");
  assert.equal(outputs["secret-count"], "2");
});

test("export-to: file masks each rendered line", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "file",
    file: ".env",
  });
  await run({
    core: h.core,
    fetch: stubFetch({
      data: { format: "dotenv", filename: ".env", content: "A=\"1\"\n", secretCount: 1 },
    }),
    writeSecretFile: async () => {},
  });
  assert.ok(h.logs.includes(`::add-mask::A="1"`));
});

test("export-to: outputs warns that outputs are persisted", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "outputs",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  const outputs = parseCommandFile(h.files.get("/tmp/github_output") ?? "");
  assert.equal(outputs.API_KEY, "sk-live-1");
  assert.ok(h.logs.some((line) => line.startsWith("::warning::") && line.includes("stored in the workflow run")));
});

test("export-to: none fetches without writing", async () => {
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "none",
  });
  await run({ core: h.core, fetch: stubFetch(runtimePayload) });

  assert.equal(parseCommandFile(h.files.get("/tmp/github_env") ?? "").API_KEY, undefined);
  const outputs = parseCommandFile(h.files.get("/tmp/github_output") ?? "");
  assert.equal(outputs["secret-count"], "2");
  // Values are still masked, because they were fetched into this process.
  assert.ok(h.logs.includes("::add-mask::sk-live-1"));
});

test("invalid export-to and format are rejected", async () => {
  const bad = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "smtp",
  });
  await assert.rejects(() => run({ core: bad.core }), /export-to must be one of/);

  const badFormat = harness({
    "api-url": "https://himitsu.example.com",
    token: TOKEN,
    project: "p1",
    environment: "e1",
    "export-to": "file",
    file: ".env",
    format: "yaml",
  });
  await assert.rejects(() => run({ core: badFormat.core }), /format must be one of/);
});

test("missing required inputs fail with a clear message", async () => {
  const h = harness({ "api-url": "https://himitsu.example.com" });
  await assert.rejects(() => run({ core: h.core }), /Input required and not supplied: token/);
});

test("a malformed token is rejected before any request is sent", async () => {
  let called = false;
  const h = harness({
    "api-url": "https://himitsu.example.com",
    token: "himi_short",
    project: "p1",
    environment: "e1",
  });
  await assert.rejects(
    () =>
      run({
        core: h.core,
        fetch: (async () => {
          called = true;
          return new Response("{}");
        }) as unknown as typeof fetch,
      }),
    /token is malformed/,
  );
  assert.equal(called, false, "a request was sent with a malformed token");
});

test("boolean inputs reject non-boolean text", () => {
  const h = harness({ mask: "maybe" });
  assert.throws(() => h.core.booleanInput("mask", true), /must be a boolean/);
});

test("list inputs split on commas and newlines", () => {
  const h = harness({ include: "A, B\nC,\n\n D " });
  assert.deepEqual(h.core.listInput("include"), ["A", "B", "C", "D"]);
});

test("API errors surface code and request id", async () => {
  const client = new HimitsuClient({
    apiUrl: "https://himitsu.example.com",
    token: TOKEN,
    maxAttempts: 1,
    fetch: stubFetch(
      { error: { code: "API_SCOPE_FORBIDDEN", message: "scope mismatch", requestId: "req-9" } },
      403,
    ),
  });
  await assert.rejects(
    () => client.runtimeConfig("p1", "e1"),
    (error: unknown) =>
      error instanceof HimitsuError &&
      error.code === "API_SCOPE_FORBIDDEN" &&
      error.message.includes("req-9"),
  );
});

test("the client retries 5xx and stops on 4xx", async () => {
  let calls = 0;
  const retrying = new HimitsuClient({
    apiUrl: "https://himitsu.example.com",
    token: TOKEN,
    sleep: async () => {},
    fetch: (async () => {
      calls += 1;
      if (calls < 3) return new Response("{}", { status: 503 });
      return new Response(JSON.stringify(runtimePayload), { status: 200 });
    }) as unknown as typeof fetch,
  });
  const config = await retrying.runtimeConfig("p1", "e1");
  assert.equal(config.configVersion, 12);
  assert.equal(calls, 3);

  let forbiddenCalls = 0;
  const failing = new HimitsuClient({
    apiUrl: "https://himitsu.example.com",
    token: TOKEN,
    sleep: async () => {},
    fetch: (async () => {
      forbiddenCalls += 1;
      return new Response(JSON.stringify({ error: { code: "FORBIDDEN", message: "no" } }), { status: 403 });
    }) as unknown as typeof fetch,
  });
  await assert.rejects(() => failing.runtimeConfig("p1", "e1"));
  assert.equal(forbiddenCalls, 1);
});

test("a response without a data field is rejected", async () => {
  const client = new HimitsuClient({
    apiUrl: "https://himitsu.example.com",
    token: TOKEN,
    maxAttempts: 1,
    fetch: stubFetch({ unexpected: true }),
  });
  await assert.rejects(() => client.runtimeConfig("p1", "e1"), /no data field/);
});

test("writing to a command file fails loudly outside a runner", async () => {
  const runtime: Runtime = { env: {}, log: () => {}, appendCommandFile: async () => {} };
  const core = new ActionCore(runtime);
  await assert.rejects(() => core.setOutput("a", "b"), /GITHUB_OUTPUT is not set/);
});

test("environment names containing newlines are refused", async () => {
  const h = harness({});
  await assert.rejects(() => h.core.exportVariable("BAD\nNAME", "v"), /newline/);
});
