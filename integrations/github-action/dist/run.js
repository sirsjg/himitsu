import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { HimitsuClient } from "./himitsu.js";
const EXPORT_TARGETS = ["env", "file", "outputs", "none"];
const FILE_FORMATS = ["dotenv", "json", "shell"];
/** A valid POSIX environment variable name. */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/**
 * Writes a file containing secrets with owner-only permissions.
 *
 * The mode is set before the content is written so the plaintext is never
 * momentarily world-readable on a shared runner.
 */
async function defaultWriteSecretFile(path, content) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content, { encoding: "utf8", mode: 0o600 });
    await chmod(path, 0o600);
}
export async function run(dependencies) {
    const { core } = dependencies;
    const apiUrl = core.input("api-url", { required: true });
    const token = core.input("token", { required: true });
    const projectId = core.input("project", { required: true });
    const environmentId = core.input("environment", { required: true });
    const exportTo = parseExportTarget(core.input("export-to", { default: "env" }));
    const shouldMask = core.booleanInput("mask", true);
    const prefix = core.input("prefix");
    const include = new Set(core.listInput("include"));
    const exclude = new Set(core.listInput("exclude"));
    if (prefix !== "" && !ENV_NAME.test(prefix)) {
        throw new Error(`prefix must be a valid environment variable prefix, got ${JSON.stringify(prefix)}`);
    }
    // The token is an input, not a repository secret in every workflow, so mask
    // it explicitly. Doing this first means even an error thrown below cannot
    // echo it.
    if (shouldMask)
        core.mask(token);
    const client = new HimitsuClient({
        apiUrl,
        token,
        ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    });
    if (exportTo === "file") {
        await writeExportFile(dependencies, client, projectId, environmentId, shouldMask);
        return;
    }
    const config = await client.runtimeConfig(projectId, environmentId);
    const selected = selectSecrets(config.secrets, include, exclude);
    // Mask every value before anything else can observe them, including the
    // summary lines written further down.
    if (shouldMask) {
        for (const value of Object.values(selected))
            core.mask(value);
    }
    const keys = Object.keys(selected).sort();
    switch (exportTo) {
        case "env": {
            const rejected = [];
            for (const key of keys) {
                const name = `${prefix}${key}`;
                if (!ENV_NAME.test(name)) {
                    rejected.push(name);
                    continue;
                }
                await core.exportVariable(name, selected[key]);
            }
            if (rejected.length > 0) {
                // Naming a rejected key is safe; naming its value would not be.
                core.warning(`Skipped ${rejected.length} secret(s) whose key is not a valid environment variable name: ${rejected.join(", ")}`);
            }
            core.info(`Exported ${keys.length - rejected.length} secret(s) to the environment.`);
            break;
        }
        case "outputs": {
            for (const key of keys) {
                await core.setOutput(`${prefix}${key}`, selected[key]);
            }
            core.warning("Secrets written to step outputs are stored in the workflow run. Prefer export-to: env unless a downstream step needs them as outputs.");
            core.info(`Exported ${keys.length} secret(s) as step outputs.`);
            break;
        }
        case "none":
            core.info(`Fetched ${keys.length} secret(s); export-to is "none" so nothing was written.`);
            break;
    }
    await core.setOutput("secret-count", String(keys.length));
    await core.setOutput("config-version", String(config.configVersion));
    // Keys are metadata, not secrets, and are what a workflow needs to assert on.
    await core.setOutput("keys", keys.join(","));
}
async function writeExportFile(dependencies, client, projectId, environmentId, shouldMask) {
    const { core } = dependencies;
    const format = parseFormat(core.input("format", { default: "dotenv" }));
    const path = core.input("file", { required: true });
    const exported = await client.export(projectId, environmentId, format);
    // The rendered document contains every value; mask the whole blob so an
    // accidental `cat` of the file in a later step is redacted too.
    if (shouldMask) {
        for (const line of exported.content.split("\n")) {
            const value = line.trim();
            if (value !== "")
                core.mask(value);
        }
    }
    const write = dependencies.writeSecretFile ?? defaultWriteSecretFile;
    await write(resolve(path), exported.content);
    core.info(`Wrote ${exported.secretCount} secret(s) to ${path} as ${format} (mode 0600).`);
    core.warning(`${path} contains plaintext secrets. Delete it before uploading artifacts or caching this workspace.`);
    await core.setOutput("secret-count", String(exported.secretCount));
    await core.setOutput("file", path);
}
/** Applies include/exclude filters. include, when non-empty, is a strict allowlist. */
export function selectSecrets(secrets, include, exclude) {
    const selected = {};
    for (const [key, value] of Object.entries(secrets)) {
        if (include.size > 0 && !include.has(key))
            continue;
        if (exclude.has(key))
            continue;
        selected[key] = value;
    }
    return selected;
}
function parseExportTarget(value) {
    if (EXPORT_TARGETS.includes(value))
        return value;
    throw new Error(`export-to must be one of ${EXPORT_TARGETS.join(", ")}, got ${JSON.stringify(value)}`);
}
function parseFormat(value) {
    if (FILE_FORMATS.includes(value))
        return value;
    throw new Error(`format must be one of ${FILE_FORMATS.join(", ")}, got ${JSON.stringify(value)}`);
}
