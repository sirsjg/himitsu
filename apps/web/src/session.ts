export interface SessionOrganization {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly role: "owner" | "admin" | "member" | "read_only";
  readonly active: boolean;
}

export interface SessionView {
  readonly user: { readonly id: string; readonly email: string };
  readonly organizations: readonly SessionOrganization[];
  readonly activeOrgId: string | null;
  readonly expiresAt: string;
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
  }
}

// Must match the profiles in @himitsu/auth; the cookie is intentionally readable by scripts.
// The unprefixed name is used when the server runs with HIMITSU_INSECURE_HTTP_COOKIES (plain-HTTP local dev).
const CSRF_COOKIES = ["__Host-himitsu_csrf", "himitsu_csrf"] as const;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function csrfToken(): string | null {
  for (const name of CSRF_COOKIES) {
    const value = readCookie(name);
    if (value !== null) return value;
  }
  return null;
}

export function readCookie(name: string, header = typeof document === "undefined" ? "" : document.cookie): string | null {
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0 || pair.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(pair.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

export type RequestFunction = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Session-aware fetch: sends cookies, attaches the CSRF token to mutating requests,
 * and returns to the sign-in screen when the session has expired.
 */
export const apiFetch: RequestFunction = async (input, init) => {
  const method = (init?.method ?? "GET").toUpperCase();
  const csrf = SAFE_METHODS.has(method) ? null : csrfToken();
  const response = await fetch(input, {
    credentials: "same-origin",
    ...init,
    headers: { ...init?.headers, ...(csrf === null ? {} : { "x-csrf-token": csrf }) },
  });
  if (response.status === 401 && typeof window !== "undefined" && window.location.pathname.startsWith("/app")) {
    window.location.assign("/login?reason=expired");
  }
  return response;
};

async function requestJson<T>(
  path: string,
  init: RequestInit | undefined,
  request: RequestFunction,
): Promise<T> {
  const response = await request(path, {
    credentials: "same-origin",
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });
  const payload = await response.json().catch(() => null) as
    | { data?: T; error?: { code?: string; message?: string } }
    | null;
  if (!response.ok) {
    throw new ApiRequestError(
      response.status,
      payload?.error?.code ?? "REQUEST_FAILED",
      payload?.error?.message ?? `The request could not be completed (${response.status}).`,
    );
  }
  if (payload?.data === undefined) throw new ApiRequestError(response.status, "MALFORMED_RESPONSE", "The response was incomplete.");
  return payload.data;
}

/** Returns the active session, or null when the browser has no valid session cookie. */
export async function fetchSession(request: RequestFunction = (input, init) => fetch(input, init)): Promise<SessionView | null> {
  try {
    return await requestJson<SessionView>("/api/v1/session", undefined, request);
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 401) return null;
    throw error;
  }
}

export async function login(email: string, password: string, request: RequestFunction = apiFetch): Promise<SessionView> {
  return requestJson("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }, request);
}

export async function signup(email: string, password: string, request: RequestFunction = apiFetch): Promise<{ userId: string }> {
  return requestJson("/api/v1/auth/signup", { method: "POST", body: JSON.stringify({ email, password }) }, request);
}

export async function logout(request: RequestFunction = apiFetch): Promise<void> {
  await requestJson("/api/v1/auth/logout", { method: "POST" }, request);
}

export async function verifyEmail(token: string, request: RequestFunction = apiFetch): Promise<void> {
  await requestJson("/api/v1/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) }, request);
}

export async function resendVerification(email: string, request: RequestFunction = apiFetch): Promise<void> {
  await requestJson("/api/v1/auth/resend-verification", { method: "POST", body: JSON.stringify({ email }) }, request);
}

export async function requestPasswordReset(email: string, request: RequestFunction = apiFetch): Promise<void> {
  await requestJson("/api/v1/auth/password-reset", { method: "POST", body: JSON.stringify({ email }) }, request);
}

export async function confirmPasswordReset(token: string, password: string, request: RequestFunction = apiFetch): Promise<void> {
  await requestJson("/api/v1/auth/password-reset/confirm", { method: "POST", body: JSON.stringify({ token, password }) }, request);
}

export async function switchOrganization(orgId: string, request: RequestFunction = apiFetch): Promise<SessionView> {
  return requestJson("/api/v1/session/organization", { method: "POST", body: JSON.stringify({ orgId }) }, request);
}

export async function createOrganization(
  name: string,
  slug: string,
  request: RequestFunction = apiFetch,
): Promise<{ organization: { id: string; name: string; slug: string }; session: SessionView }> {
  return requestJson("/api/v1/organizations", { method: "POST", body: JSON.stringify({ name, slug }) }, request);
}

export async function acceptInvitation(token: string, request: RequestFunction = apiFetch): Promise<SessionView> {
  return requestJson("/api/v1/invitations/accept", { method: "POST", body: JSON.stringify({ token }) }, request);
}
