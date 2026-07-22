import { createHash } from "node:crypto";
import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, requirePermission } from "@himitsu/authz";
import type { SecretService } from "@himitsu/secrets";
import type { TenantTransaction } from "@himitsu/tenancy";

export type FindingType =
  | "missing_key"
  | "empty_value"
  | "placeholder_value"
  | "naming_violation"
  | "case_duplicate";
export type FindingSeverity = "warning" | "error";
export type FindingDisposition = "acknowledged" | "ignored";

export class ConsistencyError extends Error {
  readonly code: "INVALID_INPUT" | "NOT_FOUND";

  constructor(code: ConsistencyError["code"], message: string) {
    super(message);
    this.name = "ConsistencyError";
    this.code = code;
  }
}

export interface ConsistencyEnvironment {
  readonly id: string;
  readonly slug: string;
}

export interface ConsistencySecretValue {
  readonly secretId: string;
  readonly environmentId: string;
  readonly key: string;
  readonly value: string;
}

export interface ConsistencyFinding {
  readonly id: string;
  readonly type: FindingType;
  readonly severity: FindingSeverity;
  readonly key: string;
  readonly keys: readonly string[];
  readonly environmentIds: readonly string[];
  readonly missingEnvironmentIds: readonly string[];
  readonly disposition: FindingDisposition | null;
  readonly dispositionNote: string | null;
  readonly dispositionUpdatedAt: Date | null;
}

interface BaseFinding extends Omit<ConsistencyFinding, "disposition" | "dispositionNote" | "dispositionUpdatedAt"> {}

export interface ConsistencyReport {
  readonly projectId: string;
  readonly sourceFingerprint: string;
  readonly computedAt: Date;
  readonly cached: boolean;
  readonly findings: readonly ConsistencyFinding[];
  readonly counts: Readonly<Record<FindingSeverity, number>>;
}

interface EnvironmentRow {
  id: string;
  slug: string;
  updated_at: Date;
}

interface SecretRow {
  id: string;
  environment_id: string;
  key: string;
  current_version: number;
  updated_at: Date;
}

interface CacheRow {
  source_fingerprint: string;
  findings: unknown;
  computed_at: Date;
}

interface StateRow {
  finding_id: string;
  disposition: FindingDisposition;
  note: string | null;
  updated_at: Date;
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

const conventionalKey = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
const placeholder = /^(?:change[-_ ]?me|todo|tbd|placeholder|replace[-_ ]?me|your[-_].+|<[^>]+>|\$\{[^}]+\}|x{3,})$/i;

function findingId(
  projectId: string,
  type: FindingType,
  normalizedKey: string,
  environmentIds: readonly string[],
  keys: readonly string[],
): string {
  return createHash("sha256")
    .update(JSON.stringify([projectId, type, normalizedKey, [...environmentIds].sort(), [...keys].sort()]))
    .digest("hex");
}

function baseFinding(
  projectId: string,
  type: FindingType,
  severity: FindingSeverity,
  key: string,
  keys: readonly string[],
  environmentIds: readonly string[],
  missingEnvironmentIds: readonly string[] = [],
): BaseFinding {
  return {
    id: findingId(projectId, type, key.toUpperCase(), environmentIds, keys),
    type,
    severity,
    key,
    keys: [...keys].sort(),
    environmentIds: [...environmentIds].sort(),
    missingEnvironmentIds: [...missingEnvironmentIds].sort(),
  };
}

export function analyzeConsistency(
  projectId: string,
  environments: readonly ConsistencyEnvironment[],
  secrets: readonly ConsistencySecretValue[],
): readonly BaseFinding[] {
  const environmentIds = [...new Set(environments.map(({ id }) => id))].sort();
  const knownEnvironments = new Set(environmentIds);
  const activeSecrets = secrets.filter(({ environmentId }) => knownEnvironments.has(environmentId));
  const byNormalizedKey = new Map<string, ConsistencySecretValue[]>();
  for (const secret of activeSecrets) {
    const normalized = secret.key.toUpperCase();
    const existing = byNormalizedKey.get(normalized) ?? [];
    existing.push(secret);
    byNormalizedKey.set(normalized, existing);
  }
  const findings: BaseFinding[] = [];
  for (const [normalized, matches] of [...byNormalizedKey.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const keys = [...new Set(matches.map(({ key }) => key))].sort();
    const present = [...new Set(matches.map(({ environmentId }) => environmentId))].sort();
    const missing = environmentIds.filter((id) => !present.includes(id));
    if (missing.length !== 0) {
      findings.push(baseFinding(projectId, "missing_key", "error", normalized, keys, present, missing));
    }
    if (keys.length > 1) {
      findings.push(baseFinding(projectId, "case_duplicate", "error", normalized, keys, present));
    }
    for (const key of keys.filter((candidate) => !conventionalKey.test(candidate))) {
      const affected = matches.filter((secret) => secret.key === key).map(({ environmentId }) => environmentId);
      findings.push(baseFinding(projectId, "naming_violation", "warning", key, [key], affected));
    }
  }
  for (const secret of activeSecrets) {
    if (secret.value.trim().length === 0) {
      findings.push(baseFinding(
        projectId,
        "empty_value",
        "error",
        secret.key,
        [secret.key],
        [secret.environmentId],
      ));
    } else if (placeholder.test(secret.value.trim())) {
      findings.push(baseFinding(
        projectId,
        "placeholder_value",
        "warning",
        secret.key,
        [secret.key],
        [secret.environmentId],
      ));
    }
  }
  return findings.sort((left, right) =>
    left.severity.localeCompare(right.severity)
    || left.type.localeCompare(right.type)
    || left.key.localeCompare(right.key)
    || left.id.localeCompare(right.id),
  );
}

export class ConsistencyService {
  readonly #resolver: AuthorizationContextResolver;
  readonly #secrets: SecretService;
  readonly #audit: AuditRecorder;

  constructor(
    resolver: AuthorizationContextResolver,
    secrets: SecretService,
    audit: TransactionalAuditLog,
  ) {
    this.#resolver = resolver;
    this.#secrets = secrets;
    this.#audit = audit;
  }

  async compute(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
  ): Promise<ConsistencyReport> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "secret.read");
    const project = await transaction.query("SELECT 1 FROM projects WHERE id = $1 AND deleted_at IS NULL", [projectId]);
    if (project.rowCount !== 1) throw new ConsistencyError("NOT_FOUND", "Project not found");
    const [environmentResult, secretResult] = await Promise.all([
      transaction.query<EnvironmentRow>(
        `SELECT id, slug, updated_at FROM environments
         WHERE project_id = $1 AND deleted_at IS NULL ORDER BY id`,
        [projectId],
      ),
      transaction.query<SecretRow>(
        `SELECT s.id, s.environment_id, s.key, s.current_version, s.updated_at
         FROM secrets s JOIN environments e ON e.id = s.environment_id
         WHERE s.project_id = $1 AND s.deleted_at IS NULL AND e.deleted_at IS NULL
         ORDER BY s.id`,
        [projectId],
      ),
    ]);
    const fingerprint = sourceFingerprint(environmentResult.rows, secretResult.rows);
    const cached = await transaction.query<CacheRow>(
      `SELECT source_fingerprint, findings, computed_at
       FROM consistency_report_cache WHERE project_id = $1 AND source_fingerprint = $2`,
      [projectId, fingerprint],
    );
    const cachedRow = cached.rows[0];
    if (cachedRow !== undefined) {
      return this.#report(
        transaction,
        projectId,
        fingerprint,
        cachedRow.computed_at,
        true,
        parseFindings(cachedRow.findings),
      );
    }
    const values: ConsistencySecretValue[] = [];
    for (const secret of secretResult.rows) {
      const decrypted = await this.#secrets.get(transaction, actorUserId, secret.id);
      values.push({
        secretId: secret.id,
        environmentId: secret.environment_id,
        key: secret.key,
        value: decrypted.value,
      });
    }
    const computedAt = new Date();
    const findings = analyzeConsistency(
      projectId,
      environmentResult.rows.map(({ id, slug }) => ({ id, slug })),
      values,
    );
    const stored = await transaction.query<{ computed_at: Date }>(
      `INSERT INTO consistency_report_cache
        (org_id, project_id, source_fingerprint, findings, computed_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (org_id, project_id) DO UPDATE
         SET source_fingerprint = EXCLUDED.source_fingerprint,
             findings = EXCLUDED.findings,
             computed_at = EXCLUDED.computed_at
       RETURNING computed_at`,
      [transaction.orgId, projectId, fingerprint, JSON.stringify(findings), computedAt],
    );
    return this.#report(
      transaction,
      projectId,
      fingerprint,
      stored.rows[0]?.computed_at ?? computedAt,
      false,
      findings,
    );
  }

  async setDisposition(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    findingIdValue: string,
    disposition: FindingDisposition,
    note?: string | null,
  ): Promise<ConsistencyFinding> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.update");
    const report = await this.compute(transaction, actorUserId, projectId);
    const finding = report.findings.find(({ id }) => id === findingIdValue);
    if (finding === undefined) throw new ConsistencyError("NOT_FOUND", "Consistency finding not found");
    const normalizedNote = dispositionNote(note);
    const state = await transaction.query<StateRow>(
      `INSERT INTO consistency_finding_states
        (org_id, project_id, finding_id, disposition, note, updated_by_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (org_id, project_id, finding_id) DO UPDATE
         SET disposition = EXCLUDED.disposition, note = EXCLUDED.note,
             updated_by_user_id = EXCLUDED.updated_by_user_id, updated_at = now()
       RETURNING finding_id, disposition, note, updated_at`,
      [transaction.orgId, projectId, findingIdValue, disposition, normalizedNote, actorUserId],
    );
    const updated = state.rows[0];
    if (updated === undefined) throw new Error("Finding state upsert returned no row");
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: disposition === "ignored" ? "consistency.ignored" : "consistency.acknowledged",
      resource: { type: "consistency_finding", id: findingIdValue },
      projectId,
      after: { disposition, findingType: finding.type, severity: finding.severity },
    });
    return withState(finding, updated);
  }

  async clearDisposition(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    findingIdValue: string,
  ): Promise<void> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.update");
    const deleted = await transaction.query(
      "DELETE FROM consistency_finding_states WHERE project_id = $1 AND finding_id = $2",
      [projectId, findingIdValue],
    );
    if (deleted.rowCount !== 1) throw new ConsistencyError("NOT_FOUND", "Consistency finding state not found");
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "consistency.cleared",
      resource: { type: "consistency_finding", id: findingIdValue },
      projectId,
    });
  }

  async #report(
    transaction: TenantTransaction,
    projectId: string,
    fingerprint: string,
    computedAt: Date,
    cached: boolean,
    findings: readonly BaseFinding[],
  ): Promise<ConsistencyReport> {
    const states = await transaction.query<StateRow>(
      `SELECT finding_id, disposition, note, updated_at
       FROM consistency_finding_states WHERE project_id = $1`,
      [projectId],
    );
    const stateById = new Map(states.rows.map((state) => [state.finding_id, state]));
    const merged = findings.map((finding) => {
      const state = stateById.get(finding.id);
      return state === undefined ? withoutState(finding) : withState(finding, state);
    });
    return {
      projectId,
      sourceFingerprint: fingerprint,
      computedAt,
      cached,
      findings: merged,
      counts: {
        error: merged.filter(({ severity }) => severity === "error").length,
        warning: merged.filter(({ severity }) => severity === "warning").length,
      },
    };
  }
}

function sourceFingerprint(environments: readonly EnvironmentRow[], secrets: readonly SecretRow[]): string {
  return createHash("sha256").update(JSON.stringify([
    environments.map((row) => [row.id, row.slug, row.updated_at.toISOString()]),
    secrets.map((row) => [row.id, row.environment_id, row.key, row.current_version, row.updated_at.toISOString()]),
  ])).digest("hex");
}

function dispositionNote(note: string | null | undefined): string | null {
  if (note === null || note === undefined || note.trim() === "") return null;
  const normalized = note.trim();
  if (normalized.length > 1000) throw new ConsistencyError("INVALID_INPUT", "Disposition note cannot exceed 1000 characters");
  return normalized;
}

function withoutState(finding: BaseFinding): ConsistencyFinding {
  return { ...finding, disposition: null, dispositionNote: null, dispositionUpdatedAt: null };
}

function withState(finding: BaseFinding | ConsistencyFinding, state: StateRow): ConsistencyFinding {
  return {
    ...finding,
    disposition: state.disposition,
    dispositionNote: state.note,
    dispositionUpdatedAt: state.updated_at,
  };
}

function parseFindings(value: unknown): readonly BaseFinding[] {
  if (!Array.isArray(value)) throw new ConsistencyError("INVALID_INPUT", "Cached consistency report is invalid");
  return value.map((candidate) => {
    if (
      typeof candidate !== "object"
      || candidate === null
      || typeof (candidate as { id?: unknown }).id !== "string"
      || typeof (candidate as { type?: unknown }).type !== "string"
      || typeof (candidate as { severity?: unknown }).severity !== "string"
      || typeof (candidate as { key?: unknown }).key !== "string"
      || !Array.isArray((candidate as { keys?: unknown }).keys)
      || !Array.isArray((candidate as { environmentIds?: unknown }).environmentIds)
      || !Array.isArray((candidate as { missingEnvironmentIds?: unknown }).missingEnvironmentIds)
    ) throw new ConsistencyError("INVALID_INPUT", "Cached consistency report is invalid");
    return candidate as BaseFinding;
  });
}
