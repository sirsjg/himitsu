import { readFile } from "node:fs/promises";
import { ApiKeyService } from "@himitsu/api-keys";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthService, insecureCookieProfile, secureCookieProfile } from "@himitsu/auth";
import { AuthorizationContextResolver } from "@himitsu/authz";
import { ConsistencyService } from "@himitsu/consistency";
import { LocalMasterKey } from "@himitsu/crypto";
import { EnvironmentService } from "@himitsu/environments";
import { ProjectService } from "@himitsu/projects";
import { SecretService } from "@himitsu/secrets";
import { TenantDatabase, TenancyService } from "@himitsu/tenancy";
import { Pool } from "pg";
import { emailDelivery } from "./email.js";
import { buildApi } from "./index.js";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positivePort(value: string | undefined): number {
  const port = Number(value ?? "3000");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("PORT must be between 1 and 65535");
  return port;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

async function masterKey(): Promise<string> {
  const file = process.env.HIMITSU_MASTER_KEY_FILE?.trim();
  return file ? (await readFile(file, "utf8")).trim() : required("HIMITSU_MASTER_KEY_BASE64");
}

// Mode is chosen in ./email.ts: a RESEND_API_KEY selects real delivery, and its absence
// keeps the previous "noop" behaviour, which drops mail and so leaves signup unable to
// complete. Resolved before anything else so a misconfigured mailer fails at startup
// rather than silently dropping the first verification email.
const delivery = emailDelivery();
console.log(JSON.stringify({ level: "info", msg: `email delivery mode: ${delivery.mode}` }));
if (delivery.mode === "noop") {
  console.log(JSON.stringify({
    level: "warn",
    msg: "email delivery is disabled: signup, password reset and invitations cannot complete. Set RESEND_API_KEY to enable delivery.",
  }));
}
const insecureCookies = process.env.HIMITSU_INSECURE_HTTP_COOKIES?.trim() === "true";
if (insecureCookies) {
  console.log(JSON.stringify({ level: "warn", msg: "HIMITSU_INSECURE_HTTP_COOKIES is enabled: session cookies are sent without the Secure flag. Local development only." }));
}
const pool = new Pool({ connectionString: required("DATABASE_URL"), max: positiveInteger(process.env.DATABASE_POOL_SIZE, 20, "DATABASE_POOL_SIZE") });
const audit = new TransactionalAuditLog(pool);
const resolver = new AuthorizationContextResolver();
const database = new TenantDatabase(pool);
const secrets = new SecretService(
  resolver,
  audit,
  LocalMasterKey.fromBase64(process.env.HIMITSU_MASTER_KEY_ID?.trim() || "local-v1", await masterKey()),
);
const app = await buildApi({
  database,
  tenancy: new TenancyService(database, delivery.tenancy, audit),
  auth: new AuthService(pool, delivery.auth),
  apiKeys: new ApiKeyService(pool, resolver, audit),
  audit,
  projects: new ProjectService(resolver, audit),
  environments: new EnvironmentService(resolver, audit),
  secrets,
  consistency: new ConsistencyService(resolver, secrets, audit),
  readiness: async () => { await pool.query("SELECT 1"); },
  logger: true,
  cookies: insecureCookies ? insecureCookieProfile : secureCookieProfile,
});

pool.on("error", (error) => app.log.error({ err: error }, "unexpected idle PostgreSQL client error"));

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  await app.close();
  await pool.end();
};
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => { void shutdown(signal).finally(() => process.exit(0)); });
}

await app.listen({ host: process.env.HOST?.trim() || "0.0.0.0", port: positivePort(process.env.PORT) });
