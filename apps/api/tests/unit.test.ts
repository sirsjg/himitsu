import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, type ApiDependencies, InMemoryRateLimiter, buildApi } from "../src/index.js";

test("API errors carry stable status and codes without exposing causes", () => {
  const error = new ApiError(401, "UNAUTHENTICATED", "Authentication required");
  assert.equal(error.statusCode, 401);
  assert.equal(error.code, "UNAUTHENTICATED");
  assert.equal(error.message, "Authentication required");
});

test("rate limits IPs and API keys independently and resets fixed windows", () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter({
    windowMs: 10_000,
    perIp: 2,
    perApiKey: 1,
    now: () => now,
  });
  assert.deepEqual(limiter.consume("ip", "127.0.0.1"), {
    allowed: true, limit: 2, remaining: 1, resetAfterSeconds: 10,
  });
  assert.equal(limiter.consume("ip", "127.0.0.1").allowed, true);
  assert.equal(limiter.consume("ip", "127.0.0.1").allowed, false);
  assert.deepEqual(limiter.consume("api_key", "key-a"), {
    allowed: true, limit: 1, remaining: 0, resetAfterSeconds: 10,
  });
  assert.equal(limiter.consume("api_key", "key-a").allowed, false);
  assert.equal(limiter.consume("api_key", "key-b").allowed, true);
  now += 10_000;
  assert.equal(limiter.consume("ip", "127.0.0.1").allowed, true);
  assert.equal(limiter.consume("api_key", "key-a").allowed, true);
});

test("operational endpoints expose liveness, database readiness, and value-free metrics", async () => {
  let ready = true;
  const app = await buildApi({
    readiness: async () => { if (!ready) throw new Error("database unavailable"); },
  } as unknown as ApiDependencies);
  try {
    const live = await app.inject({ method: "GET", url: "/health/live" });
    assert.equal(live.statusCode, 200);
    // The build stamp comes from the environment, so assert its shape rather than its
    // value: it is "dev"/"unknown" in CI and the release tag in a published image.
    const liveBody = live.json() as { status: string; version: string; commit: string };
    assert.equal(liveBody.status, "ok");
    assert.equal(typeof liveBody.version, "string");
    assert.equal(typeof liveBody.commit, "string");

    const healthy = await app.inject({ method: "GET", url: "/health/ready" });
    assert.equal(healthy.statusCode, 200);
    assert.deepEqual(healthy.json(), { status: "ready" });

    ready = false;
    const unavailable = await app.inject({ method: "GET", url: "/health/ready" });
    assert.equal(unavailable.statusCode, 503);
    assert.deepEqual(unavailable.json(), { status: "not_ready" });

    const metrics = await app.inject({ method: "GET", url: "/metrics" });
    assert.equal(metrics.statusCode, 200);
    assert.match(metrics.headers["content-type"] ?? "", /^text\/plain/);
    assert.match(metrics.body, /himitsu_http_requests_total 3/);
    assert.match(metrics.body, /himitsu_http_errors_total 1/);
    assert.doesNotMatch(metrics.body, /database unavailable/);
  } finally {
    await app.close();
  }
});
