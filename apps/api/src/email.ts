import { TOKEN_TTL_MS, type TokenDelivery } from "@himitsu/auth";
import { INVITATION_TTL_MS, type InvitationDelivery } from "@himitsu/tenancy";

/**
 * Email delivery.
 *
 * "noop" drops everything, which keeps a deployment usable before a provider is
 * configured but means no account can complete signup. "log" prints action links to
 * stdout for local development only — the links carry live tokens. "resend" sends real
 * mail through Resend's HTTP API.
 *
 * The default is chosen from the environment: a RESEND_API_KEY selects "resend", and
 * its absence leaves the previous "noop" behaviour untouched.
 */
export type EmailMode = "noop" | "log" | "resend";

export interface EmailEnvironment {
  readonly HIMITSU_EMAIL_DELIVERY?: string;
  readonly RESEND_API_KEY?: string;
  readonly HIMITSU_EMAIL_FROM?: string;
  readonly HIMITSU_EMAIL_REPLY_TO?: string;
  readonly HIMITSU_APP_ORIGIN?: string;
}

export interface EmailMessage {
  readonly to: string;
  readonly subject: string;
  readonly html: string;
  readonly text: string;
}

export type EmailTransport = (message: EmailMessage) => Promise<void>;

/**
 * Resolves the delivery mode. An explicit HIMITSU_EMAIL_DELIVERY always wins, so an
 * operator can force "noop" or "log" without deleting a key; otherwise the presence of
 * a key decides. Throws on a mode that cannot work, rather than silently degrading to
 * dropping mail — a misconfigured mailer should stop the process, not go quiet.
 */
export function resolveEmailMode(env: EmailEnvironment): EmailMode {
  const explicit = env.HIMITSU_EMAIL_DELIVERY?.trim();
  const hasKey = (env.RESEND_API_KEY?.trim() ?? "") !== "";

  if (explicit === undefined || explicit === "") return hasKey ? "resend" : "noop";
  if (explicit === "noop" || explicit === "log") return explicit;
  if (explicit === "resend") {
    if (!hasKey) throw new Error("HIMITSU_EMAIL_DELIVERY=resend requires RESEND_API_KEY");
    return "resend";
  }
  throw new Error('HIMITSU_EMAIL_DELIVERY must be "noop", "log" or "resend"');
}

// ---------------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------------

const BRAND = {
  page: "#0b0c0a",
  card: "#151714",
  inset: "#1b1d19",
  line: "#2b2f28",
  ink: "#f1f0e8",
  faint: "#8a8f84",
  accent: "#c8f169",
  accentInk: "#12170b",
  serif: "Georgia, 'Times New Roman', Times, serif",
  mono: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace",
  sans: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
} as const;

/** Organization names are user-supplied and land inside markup, so they must be escaped. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Subjects are a single header line; fold any newlines a name could smuggle in. */
function singleLine(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

function humanDuration(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return hours === 1 ? "1 hour" : `${hours} hours`;
  const days = Math.round(hours / 24);
  return days === 1 ? "1 day" : `${days} days`;
}

interface Template {
  readonly preheader: string;
  readonly eyebrow: string;
  readonly headline: string;
  /** Already-escaped HTML paragraphs. */
  readonly body: readonly string[];
  readonly ctaLabel: string;
  readonly url: string;
  readonly expiresIn: string;
  readonly footnote: string;
}

/**
 * Table-based layout with inline styles: email clients do not implement flexbox, grid,
 * stylesheets or custom properties reliably. No external assets are referenced, so
 * nothing here can be used to track whether a message was opened.
 */
function renderHtml(t: Template): string {
  const paragraphs = t.body
    .map(
      (p) =>
        `<p style="margin:0 0 16px;font-family:${BRAND.sans};font-size:15px;line-height:1.6;color:${BRAND.ink};">${p}</p>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<title>${escapeHtml(t.headline)}</title>
</head>
<body style="margin:0;padding:0;background:${BRAND.page};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(t.preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${BRAND.page};">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">

<tr><td style="padding:0 0 20px;">
  <span style="font-family:${BRAND.mono};font-size:15px;letter-spacing:0.08em;color:${BRAND.ink};">
    <span style="color:${BRAND.accent};">&#9678;</span>&nbsp;himitsu
  </span>
</td></tr>

<tr><td style="background:${BRAND.card};border:1px solid ${BRAND.line};border-radius:14px;padding:36px 32px;">
  <p style="margin:0 0 10px;font-family:${BRAND.mono};font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:${BRAND.accent};">${escapeHtml(t.eyebrow)}</p>
  <h1 style="margin:0 0 20px;font-family:${BRAND.serif};font-size:30px;line-height:1.2;font-weight:500;color:${BRAND.ink};">${escapeHtml(t.headline)}</h1>
  ${paragraphs}

  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 22px;">
    <tr><td align="center" bgcolor="${BRAND.accent}" style="border-radius:10px;">
      <a href="${escapeHtml(t.url)}" style="display:inline-block;padding:13px 26px;font-family:${BRAND.sans};font-size:15px;font-weight:600;color:${BRAND.accentInk};text-decoration:none;border-radius:10px;">${escapeHtml(t.ctaLabel)}&nbsp;&rarr;</a>
    </td></tr>
  </table>

  <p style="margin:0 0 8px;font-family:${BRAND.sans};font-size:13px;color:${BRAND.faint};">Or paste this link into your browser:</p>
  <p style="margin:0 0 22px;padding:12px 14px;background:${BRAND.inset};border:1px solid ${BRAND.line};border-radius:8px;font-family:${BRAND.mono};font-size:12px;line-height:1.5;color:${BRAND.ink};word-break:break-all;">${escapeHtml(t.url)}</p>

  <p style="margin:0;padding-top:18px;border-top:1px solid ${BRAND.line};font-family:${BRAND.sans};font-size:13px;line-height:1.6;color:${BRAND.faint};">
    This link expires in ${escapeHtml(t.expiresIn)} and can be used once. ${escapeHtml(t.footnote)}
  </p>
</td></tr>

<tr><td style="padding:20px 4px 0;">
  <p style="margin:0;font-family:${BRAND.mono};font-size:11px;line-height:1.6;letter-spacing:0.04em;color:${BRAND.faint};">
    Anyone with this link can act on your account &mdash; please don&rsquo;t forward it.
  </p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

function renderText(t: Template): string {
  return [
    "himitsu",
    "",
    t.headline,
    "",
    // Strip the markup the HTML body carries; the plain part is authored from the same source.
    ...t.body.map((p) => p.replace(/<[^>]+>/g, "")),
    "",
    `${t.ctaLabel}:`,
    t.url,
    "",
    `This link expires in ${t.expiresIn} and can be used once. ${t.footnote}`,
    "",
    "Anyone with this link can act on your account - please don't forward it.",
  ].join("\n");
}

function trimTrailingSlash(origin: string): string {
  return origin.replace(/\/+$/, "");
}

export function verificationEmail(origin: string, token: string): Omit<EmailMessage, "to"> {
  const t: Template = {
    preheader: "Confirm your address to finish setting up Himitsu.",
    eyebrow: "Confirm your address",
    headline: "One step left.",
    body: [
      "Confirm this address to activate your Himitsu account. Until it is confirmed you won&rsquo;t be able to sign in.",
    ],
    ctaLabel: "Verify email",
    url: `${trimTrailingSlash(origin)}/verify-email?token=${encodeURIComponent(token)}`,
    expiresIn: humanDuration(TOKEN_TTL_MS),
    footnote: "If you didn&rsquo;t create an account, you can ignore this message.",
  };
  return { subject: "Verify your email for Himitsu", html: renderHtml(t), text: renderText(t) };
}

export function passwordResetEmail(origin: string, token: string): Omit<EmailMessage, "to"> {
  const t: Template = {
    preheader: "Choose a new password for your Himitsu account.",
    eyebrow: "Password reset",
    headline: "Set a new password.",
    body: [
      "Someone asked to reset the password on this Himitsu account. Choose a new one using the link below.",
      "Your current password stays active until a new one is set.",
    ],
    ctaLabel: "Choose a new password",
    url: `${trimTrailingSlash(origin)}/password-reset/confirm?token=${encodeURIComponent(token)}`,
    expiresIn: humanDuration(TOKEN_TTL_MS),
    footnote: "If this wasn&rsquo;t you, ignore this message and your password will not change.",
  };
  return { subject: "Reset your Himitsu password", html: renderHtml(t), text: renderText(t) };
}

export function invitationEmail(
  origin: string,
  token: string,
  organizationName: string,
): Omit<EmailMessage, "to"> {
  const safeName = escapeHtml(organizationName);
  const t: Template = {
    preheader: `You have been invited to ${singleLine(organizationName)} on Himitsu.`,
    eyebrow: "Invitation",
    headline: "You&rsquo;ve been invited.",
    body: [
      `You have been invited to join <strong style="color:${BRAND.ink};">${safeName}</strong> on Himitsu, a workspace for managing encrypted configuration.`,
      "Accepting the invitation adds this address to the organization. You&rsquo;ll be asked to sign in or create an account first.",
    ],
    ctaLabel: "Accept invitation",
    url: `${trimTrailingSlash(origin)}/invites/${encodeURIComponent(token)}`,
    expiresIn: humanDuration(INVITATION_TTL_MS),
    footnote: "If you weren&rsquo;t expecting this, you can ignore it.",
  };
  return {
    subject: singleLine(`You're invited to ${organizationName} on Himitsu`),
    html: renderHtml(t),
    text: renderText(t),
  };
}

// ---------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------

function announce(level: "warn" | "error", fields: Record<string, unknown>): void {
  const line = JSON.stringify({ level, ...fields });
  if (level === "error") console.error(line);
  else console.log(line);
}

/**
 * Sends through Resend's HTTP API. Uses fetch rather than the SDK so that enabling real
 * mail adds no dependency to a service that handles secrets.
 *
 * Failures are logged and swallowed rather than thrown, deliberately:
 *
 *   - requestPasswordReset returns early for an address with no account and only reaches
 *     delivery for one that exists. A throw would therefore surface an error for real
 *     accounts and success for unknown ones, turning the reset form into an account
 *     enumeration oracle.
 *   - signup commits the user before delivery, so a throw would return 500 on an account
 *     that now exists, with no way for the caller to tell what happened. The address can
 *     still be confirmed through "resend verification".
 *
 * The error log is the operator's signal; it carries the provider's own message.
 */
export function resendTransport(options: {
  readonly apiKey: string;
  readonly from: string;
  readonly replyTo?: string | undefined;
  readonly fetch?: typeof globalThis.fetch | undefined;
}): EmailTransport {
  const send = options.fetch ?? globalThis.fetch;
  return async (message) => {
    try {
      const response = await send("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          authorization: `Bearer ${options.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          from: options.from,
          to: [message.to],
          subject: message.subject,
          html: message.html,
          text: message.text,
          ...(options.replyTo === undefined ? {} : { reply_to: [options.replyTo] }),
        }),
      });
      if (!response.ok) {
        const detail = await response.text().catch(() => "");
        announce("error", {
          msg: "email delivery failed",
          provider: "resend",
          status: response.status,
          // Truncated: the provider echoes request content, and this lands in shared logs.
          detail: detail.slice(0, 500),
        });
      }
    } catch (error) {
      announce("error", {
        msg: "email delivery failed",
        provider: "resend",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };
}

export interface DeliveryAdapters {
  readonly auth: TokenDelivery;
  readonly tenancy: InvitationDelivery;
  readonly mode: EmailMode;
}

/**
 * Builds the adapters the services expect. The "noop" and "log" behaviours are
 * unchanged from before Resend support existed.
 */
export function emailDelivery(env: EmailEnvironment = process.env): DeliveryAdapters {
  const mode = resolveEmailMode(env);
  const origin = trimTrailingSlash(env.HIMITSU_APP_ORIGIN?.trim() || "http://localhost:8080");

  if (mode === "noop") {
    return {
      mode,
      auth: { async sendEmailVerification() {}, async sendPasswordReset() {} },
      tenancy: { async sendOrganizationInvitation() {} },
    };
  }

  if (mode === "log") {
    const logLink = (kind: string, email: string, link: string): void => {
      announce("warn", { msg: `insecure log email delivery: ${kind}`, email, link });
    };
    return {
      mode,
      auth: {
        async sendEmailVerification(email, token) {
          logLink("email verification", email, `${origin}/verify-email?token=${encodeURIComponent(token)}`);
        },
        async sendPasswordReset(email, token) {
          logLink("password reset", email, `${origin}/password-reset/confirm?token=${encodeURIComponent(token)}`);
        },
      },
      tenancy: {
        async sendOrganizationInvitation({ email, token }) {
          logLink("organization invitation", email, `${origin}/invites/${encodeURIComponent(token)}`);
        },
      },
    };
  }

  const apiKey = env.RESEND_API_KEY?.trim() ?? "";
  const from = env.HIMITSU_EMAIL_FROM?.trim() ?? "";
  if (from === "") {
    throw new Error(
      "HIMITSU_EMAIL_FROM is required when sending through Resend, e.g. \"Himitsu <no-reply@example.com>\"",
    );
  }
  const transport = resendTransport({
    apiKey,
    from,
    replyTo: env.HIMITSU_EMAIL_REPLY_TO?.trim() || undefined,
  });

  return {
    mode,
    auth: {
      async sendEmailVerification(email, token) {
        await transport({ to: email, ...verificationEmail(origin, token) });
      },
      async sendPasswordReset(email, token) {
        await transport({ to: email, ...passwordResetEmail(origin, token) });
      },
    },
    tenancy: {
      async sendOrganizationInvitation({ email, token, organizationName }) {
        await transport({ to: email, ...invitationEmail(origin, token, organizationName) });
      },
    },
  };
}
