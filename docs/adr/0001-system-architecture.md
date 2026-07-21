# ADR 0001: System architecture and technology stack

- Status: Accepted
- Date: 2026-07-21
- Decision owners: Himitsu maintainers

## Context

Himitsu is a multi-tenant secrets-management product with three public surfaces: a browser application, a versioned HTTP API, and a command-line client. It must keep secret plaintext out of durable storage and logs, provide consistent authorization across every surface, and support both a managed service and self-hosted deployments.

## Decision

Himitsu will use a TypeScript monorepo on Node.js 22 LTS, managed with npm workspaces. TypeScript's strict mode and shared workspace packages let the API, web application, and CLI use the same domain types, validation schemas, authorization policy, and generated API client.

### Technology stack

| Concern | Choice | Rationale |
| --- | --- | --- |
| API | Fastify 5 with TypeBox schemas | Small runtime, explicit plugins, schema validation, and OpenAPI generation from route schemas. |
| Database | PostgreSQL 17 with Drizzle ORM and SQL migrations | Transactions, constraints, JSONB audit metadata, row-level security, and inspectable migrations. |
| Web | React 19, Vite, and React Router | A focused client application with fast local builds and no second server runtime. |
| CLI | Node.js executable using Commander and the generated API client | Reuses validation and API contracts while keeping secret injection and file handling local. |
| Tests | Vitest, Fastify injection, Testcontainers, and Playwright | Unit, database integration, HTTP contract, and browser coverage with production-like PostgreSQL. |
| Delivery | OCI images; Docker Compose for self-hosting; Kubernetes-compatible stateless API/web containers for managed hosting | One artifact model works locally and in production; PostgreSQL and key management remain replaceable managed dependencies. |

The initial supported production deployment is Docker Compose on a single trusted host, with an external PostgreSQL option. The same images must run on Kubernetes without local persistent application state. Static web assets are served by a dedicated unprivileged web container. Database migrations run as a separate, idempotent release job before application rollout.

### Repository and service layout

```text
apps/
  api/             Fastify server and composition root
  web/             React browser application
  cli/             himitsu command-line executable
packages/
  authz/           shared roles, permissions, and policy evaluator
  contracts/       TypeBox request/response schemas and generated OpenAPI client
  crypto/          envelope-encryption interfaces and implementations
  database/        schema, migrations, tenant-scoped repositories, transactions
  domain/          domain services with no transport dependency
  observability/   redacting logger, metrics, and tracing helpers
deploy/            container, Compose, and deployment configuration
docs/              ADRs, threat model, operations, and user documentation
```

The API is the only network-facing process allowed to read or mutate application data. HTTP handlers validate input and resolve the actor, then call transport-independent domain services. Domain services perform authorization and use repositories supplied by the database package. The web app and CLI consume the same `/api/v1` contract; they never connect directly to PostgreSQL or key-management services.

Background work initially runs through an in-process interface with PostgreSQL-backed leases. It can move into a separate worker process without changing domain behavior if load requires it.

### Encryption-key management

Himitsu uses envelope encryption:

1. Each organization has one active 256-bit data-encryption key (DEK) version and may retain inactive versions for decryption during rotation.
2. Secret values are encrypted in application memory with AES-256-GCM using a fresh, cryptographically random 96-bit nonce for every value version. The authenticated additional data binds the ciphertext to the organization, project, environment, secret, and key version.
3. PostgreSQL stores only ciphertext, nonce, authentication tag, algorithm/version metadata, and the wrapped DEK. Plaintext and unwrapped DEKs are never written to the database, audit metadata, errors, metrics, or logs.
4. A key-encryption key (KEK) wraps each DEK. Production uses a KMS/HSM adapter; self-hosting uses an explicitly configured 256-bit master key supplied at runtime through a mounted secret, never a committed file or database field.
5. Unwrapped DEKs are held in a bounded, short-lived in-memory cache and zeroed where the runtime permits when evicted. Key access is exposed only through the crypto package.

DEK rotation creates and activates a new version, then re-encrypts secret versions in resumable batches. Old wrapped DEKs remain available until every referenced ciphertext has migrated and a verification pass succeeds. KEK rotation re-wraps DEKs without decrypting secret values. Rotation progress and key identifiers are audited, but key material is not.

### Tenant isolation and authorization

Every tenant-owned table includes a non-null `org_id`. Foreign keys include `org_id` in their referenced key so a row cannot point across organizations. Unique constraints and lookup indexes begin with `org_id`.

Tenant isolation is enforced in two central layers:

- Each authenticated request opens a database transaction and sets a transaction-local organization identifier. PostgreSQL row-level-security policies require rows to match that identifier; the application role cannot bypass RLS.
- Domain code receives only an `OrgContext`-bound repository. Unscoped table access is private to the database package, and repository methods automatically include the organization key.

The API resolves session or service-token credentials into an immutable actor and active organization context. A single policy evaluator in `packages/authz` combines the organization role, optional project override, environment protection, and API-key scope. The API invokes it before domain operations; the web app uses the same policy data only to shape its interface, never as the security boundary.

Administrative migrations and maintenance jobs use a separate database role and must state their organization scope explicitly. Integration tests create at least two organizations and prove that both repository access and direct SQL through the application role deny cross-tenant reads and writes.

### Security and operational boundaries

- TLS terminates at the deployment ingress; secure, HTTP-only, SameSite cookies are used for browser sessions.
- Structured logging uses an allowlist and recursive redaction. Secret values, credentials, ciphertext payloads, cookies, and authorization headers are excluded.
- Audit events are append-only and written in the same transaction as the sensitive action.
- The API and CLI return stable error codes without echoing secret-bearing input.
- PostgreSQL backups are encrypted independently of field encryption; restore procedures require both database backup material and access to the KEK.

## Consequences

The monorepo and shared contracts reduce drift across the three clients, while PostgreSQL constraints and RLS provide defense in depth for tenant isolation. Envelope encryption keeps the database and backups from containing decryptable plaintext without separate KEK access.

This design adds operational dependencies on PostgreSQL and external key management, and it requires integration tests against a real database. Node.js cannot guarantee memory zeroization, so process isolation, short cache lifetimes, least privilege, and avoiding plaintext copies remain important controls. Self-hosted operators are responsible for protecting and backing up their mounted master key; losing it makes encrypted data unrecoverable.

## Alternatives considered

- A single full-stack React framework was rejected because a transport-independent API is the primary integration surface and the CLI must share it without coupling to a web rendering runtime.
- SQLite was rejected as the production database because row-level security, concurrent migrations, and operational tooling are central requirements. It may be used only for isolated developer utilities, never as a compatibility target.
- One global encryption key for all values was rejected because compromise would expose every tenant and rotation would require decrypting the full data set at once.
- Application-only tenant filters were rejected because one missed query would become a cross-tenant disclosure; database RLS supplies an independent enforcement boundary.
