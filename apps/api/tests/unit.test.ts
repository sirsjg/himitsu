import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, InMemoryRateLimiter } from "../src/index.js";

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
