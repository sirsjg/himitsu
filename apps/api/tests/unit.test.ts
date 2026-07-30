import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, type ApiDependencies, InMemoryRateLimiter, buildApi } from "../src/index.js";
import {
  emailDelivery,
  invitationEmail,
  passwordResetEmail,
  resendTransport,
  resolveEmailMode,
  verificationEmail,
} from "../src/email.js";

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

test("email delivery mode follows the key, and an explicit setting overrides it", () => {
  // The documented default: a key turns delivery on, its absence leaves the previous
  // drop-everything behaviour in place.
  assert.equal(resolveEmailMode({}), "noop");
  assert.equal(resolveEmailMode({ RESEND_API_KEY: "re_test" }), "resend");
  assert.equal(resolveEmailMode({ RESEND_API_KEY: "   " }), "noop", "a blank key is not a key");

  // An operator can pin a mode without deleting the key.
  assert.equal(resolveEmailMode({ RESEND_API_KEY: "re_test", HIMITSU_EMAIL_DELIVERY: "noop" }), "noop");
  assert.equal(resolveEmailMode({ RESEND_API_KEY: "re_test", HIMITSU_EMAIL_DELIVERY: "log" }), "log");

  // Asking for delivery without the means to deliver is a misconfiguration, not a
  // reason to quietly drop mail.
  assert.throws(() => resolveEmailMode({ HIMITSU_EMAIL_DELIVERY: "resend" }), /requires RESEND_API_KEY/);
  assert.throws(() => resolveEmailMode({ HIMITSU_EMAIL_DELIVERY: "smtp" }), /must be/);
});

test("resend mode refuses to start without a sender address", () => {
  assert.throws(
    () => emailDelivery({ RESEND_API_KEY: "re_test" }),
    /HIMITSU_EMAIL_FROM is required/,
  );
});

test("templates carry a single-use link, state the expiry, and escape the organization name", () => {
  const verify = verificationEmail("https://himitsu.sg1.dev/", "tok en/1");
  assert.match(verify.html, /https:\/\/himitsu\.sg1\.dev\/verify-email\?token=tok%20en%2F1/);
  assert.match(verify.text, /https:\/\/himitsu\.sg1\.dev\/verify-email\?token=tok%20en%2F1/);
  assert.match(verify.html, /expires in 30 minutes/);
  assert.doesNotMatch(verify.html, /https:\/\/himitsu\.sg1\.dev\/\/,/, "the trailing slash is trimmed");

  const reset = passwordResetEmail("https://himitsu.sg1.dev", "abc");
  assert.match(reset.html, /password-reset\/confirm\?token=abc/);
  assert.equal(reset.subject, "Reset your Himitsu password");

  // Organization names are user-supplied and land inside markup.
  const invite = invitationEmail("https://himitsu.sg1.dev", "t0k", '<img src=x onerror=alert(1)>Acme "Co"');
  assert.doesNotMatch(invite.html, /<img/, "markup in the name must not survive into the body");
  assert.match(invite.html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(invite.html, /Acme &quot;Co&quot;/);
  assert.match(invite.html, /expires in 7 days/);

  // No external references, so a message cannot report that it was opened.
  for (const message of [verify, reset, invite]) {
    assert.doesNotMatch(message.html, /<img\s/i);
    assert.doesNotMatch(message.html, /(src|href)\s*=\s*"https?:\/\/(?!himitsu\.sg1\.dev)/i);
  }
});

test("a subject cannot be broken across header lines by an organization name", () => {
  const invite = invitationEmail("https://h.example", "t", "Acme\r\nBcc: attacker@example.com");
  assert.doesNotMatch(invite.subject, /[\r\n]/);
});

test("delivery failures are logged rather than thrown, so reset cannot enumerate accounts", async () => {
  const errors: string[] = [];
  const original = console.error;
  console.error = (line: string) => { errors.push(line); };
  try {
    const failing = resendTransport({
      apiKey: "re_test",
      from: "Himitsu <no-reply@example.com>",
      fetch: async () => new Response("nope", { status: 422 }),
    });
    // Must resolve: requestPasswordReset only reaches delivery for addresses that exist,
    // so a rejection here would distinguish real accounts from unknown ones.
    await failing({ to: "a@example.com", subject: "s", html: "<p>h</p>", text: "t" });

    const throwing = resendTransport({
      apiKey: "re_test",
      from: "Himitsu <no-reply@example.com>",
      fetch: async () => { throw new Error("network down"); },
    });
    await throwing({ to: "a@example.com", subject: "s", html: "<p>h</p>", text: "t" });
  } finally {
    console.error = original;
  }
  assert.equal(errors.length, 2, "both failures are reported to the operator");
  assert.match(errors[0] ?? "", /"status":422/);
  assert.match(errors[1] ?? "", /network down/);
});

test("resend delivery posts both parts to the provider with the configured sender", async () => {
  const calls: { url: string; body: Record<string, unknown>; auth: string }[] = [];
  const transport = resendTransport({
    apiKey: "re_secret",
    from: "Himitsu <no-reply@sg1.dev>",
    replyTo: "support@sg1.dev",
    fetch: async (url, init) => {
      calls.push({
        url: String(url),
        body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        auth: String((init?.headers as Record<string, string>).authorization),
      });
      return new Response(JSON.stringify({ id: "e1" }), { status: 200 });
    },
  });
  await transport({ to: "user@example.com", ...verificationEmail("https://himitsu.sg1.dev", "tok") });

  const call = calls[0];
  assert.equal(call?.url, "https://api.resend.com/emails");
  assert.equal(call?.auth, "Bearer re_secret");
  assert.equal(call?.body.from, "Himitsu <no-reply@sg1.dev>");
  assert.deepEqual(call?.body.to, ["user@example.com"]);
  assert.deepEqual(call?.body.reply_to, ["support@sg1.dev"]);
  assert.equal(call?.body.subject, "Verify your email for Himitsu");
  // Both parts are sent: clients that refuse HTML still get a usable link.
  assert.match(String(call?.body.html), /<!doctype html>/i);
  assert.match(String(call?.body.text), /verify-email\?token=tok/);
  assert.doesNotMatch(String(call?.body.text), /</, "the plain part carries no markup");
});
