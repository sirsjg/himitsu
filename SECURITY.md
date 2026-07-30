# Security policy

## Project maturity

Himitsu is young. Read this before you put anything real in it.

- The cryptographic design and implementation have **not** been independently audited.
- There is no production deployment history and no track record of handling incidents.
- The [pre-launch security review](docs/security/review-2026-07-22.md) was performed by the author, not by a third party. Treat it as a statement of intent and a description of the controls that exist, not as external assurance.
- The project has one maintainer. There is no guaranteed response time and no support contract.

The threat model in [docs/security/threat-model.md](docs/security/threat-model.md) describes what the encryption design does and does not protect against. It is deliberately explicit about residual risk.

If you are deciding whether to trust Himitsu with production credentials, the honest answer today is: not yet, unless you have read the code yourself and accept the risk.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's [private vulnerability reporting](https://github.com/sirsjg/himitsu-enterprise/security/advisories/new) on this repository. That is the preferred channel because it keeps the report, the discussion, and the eventual advisory in one place.

Please include:

- What the issue is and which component is affected.
- The steps or proof of concept needed to reproduce it.
- The version, commit, or deployment configuration you tested.
- Any impact you have already established, especially anything that crosses a tenant boundary, exposes plaintext secret values, or bypasses an authorization check.

Reports are acknowledged on a best-effort basis. You will get a substantive reply about whether the issue is accepted, and credit in the advisory unless you ask otherwise.

### Scope

In scope, in rough priority order:

- Cross-tenant data access of any kind — organization isolation is the core security property.
- Disclosure of secret plaintext, unwrapped data-encryption keys, or the master key, including through logs, error messages, audit metadata, API responses, or backups.
- Authentication and session flaws: session fixation, CSRF bypass, API-key scope escalation, expiry or revocation bypass.
- Authorization flaws: any authenticated operation reachable without its mapped permission, protected-environment bypass, row-level-security bypass.
- SQL injection, and any path that reaches a dynamic-evaluation or process-execution sink.

Out of scope:

- Findings that require an already-compromised API host. A fully compromised API process can observe plaintext it is asked to decrypt; this is documented, accepted, and not a vulnerability in the design.
- Missing hardening on a deployment that has not followed [docs/self-hosting.md](docs/self-hosting.md) — for example running without TLS, or setting `HIMITSU_INSECURE_HTTP_COOKIES=true` outside local development.
- Denial of service through resource exhaustion, unless it is trivially cheap and unauthenticated.
- Automated scanner output without a demonstrated exploit path.

## Supported versions

There are no released versions yet and therefore no long-term support branches. Fixes land on `main`. Once tagged releases exist, this section will state which ones receive fixes.

## Operator responsibilities

Some of the security properties in the threat model depend on the deployment, not on this code:

- Terminate TLS in front of the application. Session cookies use the `__Host-` prefix and the `Secure` flag and will not work over plain HTTP.
- Store the master key separately from database backups, with access limited to operators. Losing it makes every wrapped organization key unusable and there is no recovery path.
- Keep the backup passphrase in a different location from the master key.
- Do not enable `HIMITSU_EMAIL_DELIVERY=log` anywhere logs are shared. The links it prints carry live authentication tokens.
- Keep `RESEND_API_KEY` out of the image and out of version control; supply it as a secret at runtime. It can send mail as your verified domain.
- Email delivery failures are logged rather than raised, so that a password-reset request cannot be used to tell registered addresses from unknown ones. Alert on `"msg":"email delivery failed"`; otherwise a broken mailer looks like a working one.
