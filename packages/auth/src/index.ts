import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import type { Pool, PoolClient } from "pg";

const TOKEN_BYTES = 32;
/** Lifetime of email verification and password reset tokens. Exported so delivery
 *  templates can state the expiry without hardcoding a value that could drift. */
export const TOKEN_TTL_MS = 30 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export class AuthError extends Error {
  readonly code:
    | "INVALID_INPUT"
    | "EMAIL_EXISTS"
    | "INVALID_CREDENTIALS"
    | "EMAIL_NOT_VERIFIED"
    | "INVALID_TOKEN"
    | "INVALID_SESSION"
    | "INVALID_CSRF"
    | "RATE_LIMITED";

  constructor(code: AuthError["code"], message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}

export interface TokenDelivery {
  sendEmailVerification(email: string, token: string): Promise<void>;
  sendPasswordReset(email: string, token: string): Promise<void>;
}

export interface ClientContext {
  readonly ip?: string;
  readonly userAgent?: string;
}

export interface LoginAttemptLimiterOptions {
  readonly maxFailures?: number;
  readonly windowMs?: number;
  readonly now?: () => number;
}

interface LoginAttemptBucket {
  failures: number;
  resetAt: number;
}

export class LoginAttemptLimiter {
  readonly #maxFailures: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #buckets = new Map<string, LoginAttemptBucket>();
  #operations = 0;

  constructor(options: LoginAttemptLimiterOptions = {}) {
    this.#maxFailures = positiveInteger(options.maxFailures ?? 5, "Maximum login failures");
    this.#windowMs = positiveInteger(options.windowMs ?? 15 * 60 * 1000, "Login failure window");
    this.#now = options.now ?? Date.now;
  }

  isBlocked(identities: readonly string[]): boolean {
    const now = this.#now();
    return identities.some((identity) => {
      const bucket = this.#buckets.get(identity);
      if (bucket === undefined) return false;
      if (bucket.resetAt <= now) {
        this.#buckets.delete(identity);
        return false;
      }
      return bucket.failures >= this.#maxFailures;
    });
  }

  recordFailure(identities: readonly string[]): boolean {
    const now = this.#now();
    for (const identity of identities) {
      const existing = this.#buckets.get(identity);
      const bucket = existing === undefined || existing.resetAt <= now
        ? { failures: 0, resetAt: now + this.#windowMs }
        : existing;
      bucket.failures += 1;
      this.#buckets.set(identity, bucket);
    }
    this.#operations += identities.length;
    if (this.#operations >= 1000) {
      for (const [identity, bucket] of this.#buckets) {
        if (bucket.resetAt <= now) this.#buckets.delete(identity);
      }
      this.#operations = 0;
    }
    return this.isBlocked(identities);
  }

  clear(identities: readonly string[]): void {
    for (const identity of identities) this.#buckets.delete(identity);
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

export interface SessionCredentials {
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly expiresAt: Date;
  readonly user: { readonly id: string; readonly email: string };
}

export interface AuthenticatedSession {
  readonly sessionId: string;
  readonly userId: string;
  readonly email: string;
  readonly activeOrgId: string | null;
  readonly csrfHash: Buffer;
  readonly expiresAt: Date;
}

export interface FailedSessionContext {
  readonly sessionId: string;
  readonly userId: string;
  readonly activeOrgId: string;
}

export const sessionCookie = {
  name: "__Host-himitsu_session",
  options: { httpOnly: true, secure: true, sameSite: "Strict", path: "/" },
} as const;

export const csrfCookie = {
  name: "__Host-himitsu_csrf",
  options: { httpOnly: false, secure: true, sameSite: "Strict", path: "/" },
} as const;

export interface CookieProfile {
  readonly sessionName: string;
  readonly csrfName: string;
  readonly secure: boolean;
}

export const secureCookieProfile: CookieProfile = {
  sessionName: sessionCookie.name,
  csrfName: csrfCookie.name,
  secure: true,
};

// Plain-HTTP local development only. Browsers silently drop Secure cookies on
// http origins (except some localhost allowances), which makes login appear to
// succeed while no session is stored. The __Host- prefix requires Secure, so
// the insecure profile also uses unprefixed names.
export const insecureCookieProfile: CookieProfile = {
  sessionName: "himitsu_session",
  csrfName: "himitsu_csrf",
  secure: false,
};

function serializeCookie(
  name: string,
  value: string,
  options: { readonly httpOnly: boolean; readonly maxAge: number; readonly secure: boolean },
): string {
  return [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${options.maxAge}`,
    options.secure ? "Secure" : "",
    options.httpOnly ? "HttpOnly" : "",
    "SameSite=Strict",
  ].filter(Boolean).join("; ");
}

export function sessionCookieHeaders(
  credentials: SessionCredentials,
  profile: CookieProfile = secureCookieProfile,
): readonly [string, string] {
  const maxAge = Math.max(0, Math.floor((credentials.expiresAt.getTime() - Date.now()) / 1000));
  return [
    serializeCookie(profile.sessionName, credentials.sessionToken, { httpOnly: true, maxAge, secure: profile.secure }),
    serializeCookie(profile.csrfName, credentials.csrfToken, { httpOnly: false, maxAge, secure: profile.secure }),
  ];
}

export function clearSessionCookieHeaders(profile: CookieProfile = secureCookieProfile): readonly [string, string] {
  return [
    serializeCookie(profile.sessionName, "", { httpOnly: true, maxAge: 0, secure: profile.secure }),
    serializeCookie(profile.csrfName, "", { httpOnly: false, maxAge: 0, secure: profile.secure }),
  ];
}

function token(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    throw new AuthError("INVALID_INPUT", "A valid email address is required");
  }
  return normalized;
}

function validatePassword(password: string): void {
  if (password.length < 12 || password.length > 1024) {
    throw new AuthError("INVALID_INPUT", "Password must be between 12 and 1024 characters");
  }
}

export class PasswordHasher {
  async hash(password: string): Promise<string> {
    validatePassword(password);
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1,
      hashLength: 32,
    });
  }

  async verify(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }
}

interface UserRow { id: string; email: string; password_hash: string; email_verified_at: Date | null }
interface SessionRow {
  id: string;
  user_id: string;
  email: string;
  active_org_id: string | null;
  csrf_hash: Buffer;
  expires_at: Date;
}

export class AuthService {
  readonly #pool: Pool;
  readonly #delivery: TokenDelivery;
  readonly #hasher: PasswordHasher;
  readonly #now: () => Date;
  readonly #loginAttempts: LoginAttemptLimiter;

  constructor(
    pool: Pool,
    delivery: TokenDelivery,
    options: { hasher?: PasswordHasher; now?: () => Date; loginAttempts?: LoginAttemptLimiter } = {},
  ) {
    this.#pool = pool;
    this.#delivery = delivery;
    this.#hasher = options.hasher ?? new PasswordHasher();
    this.#now = options.now ?? (() => new Date());
    this.#loginAttempts = options.loginAttempts ?? new LoginAttemptLimiter();
  }

  async signup(email: string, password: string): Promise<{ userId: string }> {
    const normalized = normalizeEmail(email);
    const passwordHash = await this.#hasher.hash(password);
    const verificationToken = token();
    const client = await this.#pool.connect();
    let userId: string;
    try {
      await client.query("BEGIN");
      const inserted = await client.query<{ id: string }>(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
        [normalized, passwordHash],
      );
      userId = inserted.rows[0]?.id ?? "";
      await client.query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        [userId, digest(verificationToken), new Date(this.#now().getTime() + TOKEN_TTL_MS)],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      if ((error as { code?: string }).code === "23505") {
        throw new AuthError("EMAIL_EXISTS", "An account already exists for this email");
      }
      throw error;
    } finally {
      client.release();
    }
    await this.#delivery.sendEmailVerification(normalized, verificationToken);
    return { userId };
  }

  async verifyEmail(verificationToken: string): Promise<void> {
    await this.#consumeUserToken("email_verification_tokens", verificationToken, async (client, userId) => {
      await client.query("UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1", [userId]);
    });
  }

  async login(email: string, password: string, context: ClientContext = {}): Promise<SessionCredentials> {
    const normalized = normalizeEmail(email);
    const loginIdentities = [
      `account:${createHash("sha256").update(normalized, "utf8").digest("hex")}`,
      ...(context.ip === undefined ? [] : [`ip:${context.ip}`]),
    ];
    if (this.#loginAttempts.isBlocked(loginIdentities)) {
      throw new AuthError("RATE_LIMITED", "Too many login attempts; try again later");
    }
    const result = await this.#pool.query<UserRow>(
      "SELECT id, email, password_hash, email_verified_at FROM users WHERE email_normalized = $1 AND disabled_at IS NULL",
      [normalized],
    );
    const user = result.rows[0];
    if (user === undefined || !user.password_hash || !(await this.#hasher.verify(user.password_hash, password))) {
      if (this.#loginAttempts.recordFailure(loginIdentities)) {
        throw new AuthError("RATE_LIMITED", "Too many login attempts; try again later");
      }
      throw new AuthError("INVALID_CREDENTIALS", "Invalid email or password");
    }
    this.#loginAttempts.clear(loginIdentities);
    if (user.email_verified_at === null) {
      throw new AuthError("EMAIL_NOT_VERIFIED", "Email verification is required");
    }
    const sessionToken = token();
    const csrfToken = token();
    const expiresAt = new Date(this.#now().getTime() + SESSION_TTL_MS);
    await this.#pool.query(
      `INSERT INTO sessions (user_id, token_hash, csrf_hash, ip, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, digest(sessionToken), digest(csrfToken), context.ip ?? null, context.userAgent ?? null, expiresAt],
    );
    return { sessionToken, csrfToken, expiresAt, user: { id: user.id, email: user.email } };
  }

  async authenticate(sessionToken: string): Promise<AuthenticatedSession> {
    const result = await this.#pool.query<SessionRow>(
      `SELECT s.id, s.user_id, u.email, s.active_org_id, s.csrf_hash, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.disabled_at IS NULL`,
      [digest(sessionToken)],
    );
    const session = result.rows[0];
    if (session === undefined) throw new AuthError("INVALID_SESSION", "Session is invalid or expired");
    await this.#pool.query("UPDATE sessions SET last_seen_at = now() WHERE id = $1", [session.id]);
    return {
      sessionId: session.id,
      userId: session.user_id,
      email: session.email,
      activeOrgId: session.active_org_id,
      csrfHash: session.csrf_hash,
      expiresAt: session.expires_at,
    };
  }

  async failedSessionContext(sessionToken: string): Promise<FailedSessionContext | null> {
    const result = await this.#pool.query<{
      id: string;
      user_id: string;
      active_org_id: string;
    }>(
      `SELECT id, user_id, active_org_id
       FROM sessions
       WHERE token_hash = $1 AND active_org_id IS NOT NULL`,
      [digest(sessionToken)],
    );
    const session = result.rows[0];
    return session === undefined
      ? null
      : { sessionId: session.id, userId: session.user_id, activeOrgId: session.active_org_id };
  }

  verifyCsrf(session: AuthenticatedSession, csrfToken: string): void {
    const supplied = digest(csrfToken);
    if (supplied.byteLength !== session.csrfHash.byteLength || !timingSafeEqual(supplied, session.csrfHash)) {
      throw new AuthError("INVALID_CSRF", "CSRF token is invalid");
    }
  }

  async logout(sessionToken: string, csrfToken: string): Promise<void> {
    const session = await this.authenticate(sessionToken);
    this.verifyCsrf(session, csrfToken);
    await this.#pool.query("UPDATE sessions SET revoked_at = now() WHERE id = $1", [session.sessionId]);
  }

  /** Issues a fresh verification token for an unverified account; silently ignores unknown or already-verified emails. */
  async resendEmailVerification(email: string): Promise<void> {
    const normalized = normalizeEmail(email);
    const result = await this.#pool.query<{ id: string; email: string; email_verified_at: Date | null }>(
      "SELECT id, email, email_verified_at FROM users WHERE email_normalized = $1 AND disabled_at IS NULL",
      [normalized],
    );
    const user = result.rows[0];
    if (user === undefined || user.email_verified_at !== null) return;
    const verificationToken = token();
    await this.#pool.query(
      "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
      [user.id, digest(verificationToken), new Date(this.#now().getTime() + TOKEN_TTL_MS)],
    );
    await this.#delivery.sendEmailVerification(user.email, verificationToken);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const normalized = normalizeEmail(email);
    const result = await this.#pool.query<{ id: string; email: string }>(
      "SELECT id, email FROM users WHERE email_normalized = $1 AND disabled_at IS NULL",
      [normalized],
    );
    const user = result.rows[0];
    if (user === undefined) return;
    const resetToken = token();
    await this.#pool.query(
      "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
      [user.id, digest(resetToken), new Date(this.#now().getTime() + TOKEN_TTL_MS)],
    );
    await this.#delivery.sendPasswordReset(user.email, resetToken);
  }

  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    const passwordHash = await this.#hasher.hash(newPassword);
    await this.#consumeUserToken("password_reset_tokens", resetToken, async (client, userId) => {
      await client.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [passwordHash, userId]);
      await client.query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [userId]);
    });
  }

  async #consumeUserToken(
    table: "email_verification_tokens" | "password_reset_tokens",
    plaintextToken: string,
    effect: (client: PoolClient, userId: string) => Promise<void>,
  ): Promise<void> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM ${table}
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() FOR UPDATE`,
        [digest(plaintextToken)],
      );
      const record = result.rows[0];
      if (record === undefined) throw new AuthError("INVALID_TOKEN", "Token is invalid or expired");
      await effect(client, record.user_id);
      await client.query(`UPDATE ${table} SET consumed_at = now() WHERE id = $1`, [record.id]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
}
