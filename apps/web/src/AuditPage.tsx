import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";

export interface AuditEventView {
  readonly id: string;
  readonly actor: { readonly type: "user" | "api_key" | "system"; readonly id: string | null; readonly label: string };
  readonly action: string;
  readonly resource: { readonly type: string; readonly id: string | null };
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly occurredAt: string;
}

export interface AuditFilters {
  readonly actor?: string;
  readonly action?: string;
  readonly projectId?: string;
  readonly environmentId?: string;
  readonly from?: string;
  readonly to?: string;
  readonly resource?: string;
}

interface AuditExportView {
  readonly format: "csv" | "json";
  readonly filename: string;
  readonly mimeType: string;
  readonly content: string;
  readonly eventCount: number;
  readonly truncated: boolean;
}

export interface AuditClient {
  list(filters: AuditFilters, cursor?: string): Promise<{ events: readonly AuditEventView[]; nextCursor: string | null }>;
  export(filters: AuditFilters, format: "csv" | "json"): Promise<AuditExportView>;
  getRetention(): Promise<number>;
  updateRetention(days: number): Promise<number>;
}

type RequestFunction = (input: string, init?: RequestInit) => Promise<Response>;

function queryString(filters: AuditFilters): URLSearchParams {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value.trim() === "") continue;
    query.set(key, key === "from" || key === "to" ? new Date(value).toISOString() : value.trim());
  }
  return query;
}

export function createAuditClient(request: RequestFunction = (input, init) => fetch(input, init)): AuditClient {
  const json = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await request(path, { credentials: "same-origin", ...init, headers: { "content-type": "application/json", ...init?.headers } });
    if (!response.ok) {
      const payload = await response.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(payload?.error?.message ?? `Request failed (${response.status})`);
    }
    return (await response.json() as { data: T }).data;
  };
  return {
    list: (filters, cursor) => {
      const query = queryString(filters);
      query.set("limit", "50");
      if (cursor !== undefined) query.set("cursor", cursor);
      return json(`/api/v1/audit-events?${query}`);
    },
    export: (filters, format) => {
      const query = queryString(filters);
      query.set("format", format);
      return json(`/api/v1/audit-events/export?${query}`);
    },
    getRetention: async () => (await json<{ retentionDays: number }>("/api/v1/audit-settings")).retentionDays,
    updateRetention: async (retentionDays) => (await json<{ retentionDays: number }>("/api/v1/audit-settings", { method: "PATCH", body: JSON.stringify({ retentionDays }) })).retentionDays,
  };
}

const browserAuditClient = createAuditClient();

export const demoAuditEvents: readonly AuditEventView[] = [
  { id: "103", actor: { type: "user", id: "user-akari", label: "akari@example.com" }, action: "secret.updated", resource: { type: "secret", id: "DATABASE_URL" }, projectId: "project-atlas", environmentId: "production", ip: "203.0.113.18", userAgent: "Himitsu Web", metadata: { after: { version: 11 } }, occurredAt: "2026-07-22T08:42:00.000Z" },
  { id: "102", actor: { type: "api_key", id: "api-key-ci", label: "Deploy pipeline" }, action: "secret.read", resource: { type: "secret", id: "STRIPE_SECRET_KEY" }, projectId: "project-atlas", environmentId: "production", ip: "198.51.100.24", userAgent: "himitsu-cli/0.1", metadata: { details: { operation: "runtime_fetch" } }, occurredAt: "2026-07-22T08:35:00.000Z" },
  { id: "101", actor: { type: "user", id: "user-akari", label: "akari@example.com" }, action: "secret.imported", resource: { type: "environment", id: "development" }, projectId: "project-atlas", environmentId: "development", ip: "203.0.113.18", userAgent: "Himitsu Web", metadata: { details: { format: "dotenv", requested: 4 } }, occurredAt: "2026-07-22T07:58:00.000Z" },
];

const actionOptions = [
  "", "secret.created", "secret.read", "secret.updated", "secret.deleted", "secret.imported", "secret.exported",
  "project.created", "project.updated", "environment.created", "environment.updated", "api_key.created", "api_key.revoked",
  "organization.audit_retention_updated",
] as const;

export function AuditPage({
  role,
  client = browserAuditClient,
  initialEvents = demoAuditEvents,
}: {
  role: "owner" | "admin" | "member" | "read_only";
  client?: AuditClient;
  initialEvents?: readonly AuditEventView[];
}): ReactNode {
  const [draft, setDraft] = useState<AuditFilters>({});
  const [filters, setFilters] = useState<AuditFilters>({});
  const [events, setEvents] = useState<readonly AuditEventView[]>(initialEvents);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retentionDays, setRetentionDays] = useState(90);
  const sentinel = useRef<HTMLDivElement>(null);
  const allowed = role === "owner" || role === "admin";

  const load = async (replace: boolean, activeFilters = filters) => {
    if (!allowed || busy) return;
    setBusy(true);
    try {
      const page = await client.list(activeFilters, replace ? undefined : nextCursor ?? undefined);
      setEvents((current) => replace ? page.events : [...current, ...page.events]);
      setNextCursor(page.nextCursor);
      setError(null);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Audit events could not be loaded."); }
    finally { setBusy(false); }
  };

  useEffect(() => {
    if (!allowed) return;
    void load(true, {});
    void client.getRetention().then(setRetentionDays).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Retention settings could not be loaded."));
  }, [allowed, client]);

  useEffect(() => {
    const element = sentinel.current;
    if (element === null || nextCursor === null || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver((entries) => { if (entries.some(({ isIntersecting }) => isIntersecting)) void load(false); }, { rootMargin: "160px" });
    observer.observe(element);
    return () => observer.disconnect();
  }, [nextCursor, filters, busy]);

  if (!allowed) return <div className="page-stack"><PageHeading /><section className="audit-denied"><strong>Administrator access required</strong><p>Audit events and compliance exports are available only to organization owners and administrators.</p></section></div>;

  const update = (key: keyof AuditFilters, value: string) => setDraft((current) => ({ ...current, [key]: value }));
  const apply = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setFilters(draft); setNextCursor(null); void load(true, draft); };
  const download = async (format: "csv" | "json") => {
    setBusy(true);
    try {
      const exported = await client.export(filters, format);
      const url = URL.createObjectURL(new Blob([exported.content], { type: exported.mimeType }));
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = exported.filename; anchor.click(); URL.revokeObjectURL(url);
      setError(exported.truncated ? `Exported ${exported.eventCount} events (10,000 event limit reached).` : null);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Audit export failed."); }
    finally { setBusy(false); }
  };
  const saveRetention = async () => {
    setBusy(true);
    try { setRetentionDays(await client.updateRetention(retentionDays)); setError(null); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Retention could not be updated."); }
    finally { setBusy(false); }
  };

  return <div className="audit-page page-stack">
    <PageHeading />
    <section className="audit-controls">
      <form onSubmit={apply} aria-label="Audit filters">
        <label>Actor<input value={draft.actor ?? ""} onChange={(event) => update("actor", event.target.value)} placeholder="Email, key, or actor ID" /></label>
        <label>Action<select value={draft.action ?? ""} onChange={(event) => update("action", event.target.value)}>{actionOptions.map((action) => <option value={action} key={action}>{action || "All actions"}</option>)}</select></label>
        <label>Project ID<input value={draft.projectId ?? ""} onChange={(event) => update("projectId", event.target.value)} placeholder="All projects" /></label>
        <label>Environment ID<input value={draft.environmentId ?? ""} onChange={(event) => update("environmentId", event.target.value)} placeholder="All environments" /></label>
        <label>From<input type="datetime-local" value={draft.from ?? ""} onChange={(event) => update("from", event.target.value)} /></label>
        <label>To<input type="datetime-local" value={draft.to ?? ""} onChange={(event) => update("to", event.target.value)} /></label>
        <label className="audit-resource">Resource search<input value={draft.resource ?? ""} onChange={(event) => update("resource", event.target.value)} placeholder="Type or resource ID" /></label>
        <button className="primary-button" type="submit" disabled={busy}>Apply filters</button>
      </form>
      <div className="audit-tools"><label>Retention<input type="number" min="1" max="3650" value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))} /><span>days</span></label><button type="button" onClick={() => void saveRetention()} disabled={busy}>Save policy</button><i /><button type="button" onClick={() => void download("csv")} disabled={busy}>Export CSV</button><button type="button" onClick={() => void download("json")} disabled={busy}>Export JSON</button></div>
    </section>
    {error ? <p className="audit-error" role="alert">{error}</p> : null}
    <section className="audit-stream" aria-label="Audit events">
      <header><span>{events.length} loaded events</span><span>Append-only · value-safe metadata</span></header>
      {events.map((event) => <article key={event.id}>
        <time dateTime={event.occurredAt}>{new Date(event.occurredAt).toLocaleString()}</time>
        <div className={`audit-actor ${event.actor.type}`}><i /> <span><strong>{event.actor.label}</strong><small>{event.actor.type.replace("_", " ")}</small></span></div>
        <div className="audit-action"><code>{event.action}</code><span>{event.resource.type} · {event.resource.id ?? "—"}</span></div>
        <div className="audit-scope"><span>Project {event.projectId ?? "organization"}</span><span>Environment {event.environmentId ?? "—"}</span></div>
        <details><summary>Metadata</summary><pre>{JSON.stringify(event.metadata, null, 2)}</pre></details>
      </article>)}
      {events.length === 0 && !busy ? <div className="audit-empty">No audit events match these filters.</div> : null}
      <div ref={sentinel} className="audit-sentinel">{busy ? "Loading events…" : nextCursor ? <button type="button" onClick={() => void load(false)}>Load more</button> : "End of audit history"}</div>
    </section>
  </div>;
}

function PageHeading(): ReactNode {
  return <header className="page-header"><div><span>Governance</span><h1>Audit log</h1><p>Trace sensitive activity with immutable, secret-safe records. Filter, inspect, and export evidence without exposing secret values.</p></div></header>;
}
