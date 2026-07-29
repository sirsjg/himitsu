/** Minimal Himitsu API client for the GitHub Action, built on global fetch. */
const TOKEN_PATTERN = /^himi_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;
export class HimitsuError extends Error {
    status;
    code;
    requestId;
    constructor(status, code, message, requestId) {
        super(requestId === undefined ? message : `${message} (request ${requestId})`);
        this.name = "HimitsuError";
        this.status = status;
        this.code = code;
        this.requestId = requestId;
    }
}
export class HimitsuClient {
    #baseUrl;
    #token;
    #fetch;
    #maxAttempts;
    #sleep;
    constructor(options) {
        const url = new URL(options.apiUrl);
        if (url.protocol !== "https:" && url.protocol !== "http:") {
            throw new Error("api-url must use http or https");
        }
        if (!TOKEN_PATTERN.test(options.token)) {
            // Fail on shape before sending, so a truncated secret in the workflow
            // surfaces as a clear message rather than a bare 401.
            throw new Error("token is malformed (expected himi_<16 hex>_<43 chars>)");
        }
        this.#baseUrl = url.toString().replace(/\/$/, "");
        this.#token = options.token;
        this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
        this.#maxAttempts = options.maxAttempts ?? 4;
        this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    }
    /** Fetches every secret in an environment as a flat map. */
    async runtimeConfig(projectId, environmentId) {
        return this.#json(`/api/v1/projects/${encodeURIComponent(projectId)}` +
            `/environments/${encodeURIComponent(environmentId)}/secrets/runtime`);
    }
    /** Renders an environment in the requested file format. */
    async export(projectId, environmentId, format) {
        const query = new URLSearchParams({ format });
        return this.#json(`/api/v1/projects/${encodeURIComponent(projectId)}` +
            `/environments/${encodeURIComponent(environmentId)}/exports?${query.toString()}`);
    }
    async #json(path) {
        let lastError;
        for (let attempt = 1; attempt <= this.#maxAttempts; attempt += 1) {
            if (attempt > 1)
                await this.#sleep(backoffMs(attempt));
            let response;
            try {
                response = await this.#fetch(`${this.#baseUrl}${path}`, {
                    headers: {
                        authorization: `Bearer ${this.#token}`,
                        accept: "application/json",
                        "user-agent": "himitsu-github-action/1.0",
                    },
                });
            }
            catch (cause) {
                lastError = new Error(`Network error calling Himitsu: ${errorMessage(cause)}`);
                continue;
            }
            if (response.ok) {
                const payload = (await response.json().catch(() => null));
                if (payload?.data === undefined) {
                    throw new HimitsuError(response.status, "MALFORMED_RESPONSE", "API response had no data field");
                }
                return payload.data;
            }
            const error = await toError(response);
            // 429 and 5xx may pass; everything else is deterministic.
            if (response.status !== 429 && response.status < 500)
                throw error;
            lastError = error;
        }
        throw lastError ?? new Error("Himitsu request failed");
    }
}
async function toError(response) {
    const payload = (await response.json().catch(() => null));
    const detail = payload?.error;
    if (detail?.code !== undefined) {
        return new HimitsuError(response.status, detail.code, detail.message ?? "Himitsu request failed", detail.requestId);
    }
    return new HimitsuError(response.status, "HTTP_ERROR", `Himitsu request failed (${response.status})`);
}
function backoffMs(attempt) {
    const delay = Math.min(250 * 2 ** (attempt - 2), 8000);
    return delay / 2 + Math.random() * (delay / 2);
}
function errorMessage(cause) {
    return cause instanceof Error ? cause.message : String(cause);
}
