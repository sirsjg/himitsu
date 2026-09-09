import { type FormEvent, type ReactNode, useState } from "react";
import { apiFetch, type RequestFunction } from "./session.js";
import type { EnvironmentView } from "./SecretWorkspace.js";

export type EnvironmentRole = "owner" | "admin" | "member" | "read_only";

/** Mirrors the authz permission matrix: members create and edit, admins and owners also delete. */
export function environmentPermissions(role: EnvironmentRole): { readonly manage: boolean; readonly remove: boolean } {
  return { manage: role !== "read_only", remove: role === "owner" || role === "admin" };
}

export function suggestEnvironmentSlug(value: string): string {
  return value.trim().toLocaleLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

/** Raised when the API refuses a delete because the environment still holds active secrets. */
export class EnvironmentConfirmationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvironmentConfirmationError";
  }
}

export interface EnvironmentInput {
  readonly name: string;
  readonly slug: string;
  readonly protected: boolean;
}

export interface EnvironmentClient {
  list(projectId: string): Promise<readonly EnvironmentView[]>;
  create(projectId: string, input: EnvironmentInput): Promise<EnvironmentView>;
  update(projectId: string, environmentId: string, input: Partial<EnvironmentInput>): Promise<EnvironmentView>;
  remove(projectId: string, environmentId: string, confirmSecrets: boolean): Promise<EnvironmentView>;
  reorder(projectId: string, environmentIds: readonly string[]): Promise<readonly EnvironmentView[]>;
}

interface ApiEnvironment {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly protected: boolean;
}

function toView({ id, name, slug, protected: isProtected }: ApiEnvironment): EnvironmentView {
  return { id, name, slug, protected: isProtected };
}

export function createEnvironmentClient(request: RequestFunction = (input, init) => fetch(input, init)): EnvironmentClient {
  const json = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await request(path, {
      credentials: "same-origin",
      ...init,
      headers: { "content-type": "application/json", ...init?.headers },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null) as { error?: { code?: string; message?: string } } | null;
      const message = payload?.error?.message ?? `Request failed (${response.status})`;
      if (payload?.error?.code === "SECRETS_REQUIRE_CONFIRMATION") throw new EnvironmentConfirmationError(message);
      throw new Error(message);
    }
    return (await response.json() as { data: T }).data;
  };
  const base = (projectId: string) => `/api/v1/projects/${encodeURIComponent(projectId)}/environments`;
  return {
    list: async (projectId) => (await json<readonly ApiEnvironment[]>(`${base(projectId)}?limit=100`)).map(toView),
    create: async (projectId, input) => toView(await json<ApiEnvironment>(base(projectId), { method: "POST", body: JSON.stringify(input) })),
    update: async (projectId, environmentId, input) => toView(await json<ApiEnvironment>(`${base(projectId)}/${encodeURIComponent(environmentId)}`, { method: "PATCH", body: JSON.stringify(input) })),
    remove: async (projectId, environmentId, confirmSecrets) => toView(await json<ApiEnvironment>(`${base(projectId)}/${encodeURIComponent(environmentId)}${confirmSecrets ? "?confirmSecrets=true" : ""}`, { method: "DELETE" })),
    reorder: async (projectId, environmentIds) => (await json<readonly ApiEnvironment[]>(`${base(projectId)}/reorder`, { method: "POST", body: JSON.stringify({ environmentIds }) })).map(toView),
  };
}

export const browserEnvironmentClient = createEnvironmentClient(apiFetch);

/** Returns the environment list with the item at `index` shifted by `delta`, or the same list when the move is out of range. */
export function moveEnvironment(environments: readonly EnvironmentView[], index: number, delta: -1 | 1): readonly EnvironmentView[] {
  const target = index + delta;
  if (index < 0 || index >= environments.length || target < 0 || target >= environments.length) return environments;
  const next = [...environments];
  const [moved] = next.splice(index, 1);
  if (moved === undefined) return environments;
  next.splice(target, 0, moved);
  return next;
}

export function EnvironmentManager({ projectId, environments, role, secretCounts, client = browserEnvironmentClient, onCancel, onChange }: {
  projectId: string;
  environments: readonly EnvironmentView[];
  role: EnvironmentRole;
  secretCounts: Readonly<Record<string, number>>;
  client?: EnvironmentClient;
  onCancel: () => void;
  onChange: (environments: readonly EnvironmentView[]) => void;
}): ReactNode {
  const permissions = environmentPermissions(role);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [forceDeleteId, setForceDeleteId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [isProtected, setIsProtected] = useState(false);

  const run = async (action: () => Promise<void>, fallback: string) => {
    setBusy(true);
    setError(null);
    setStatus(null);
    try { await action(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : fallback); }
    finally { setBusy(false); }
  };

  const move = (index: number, delta: -1 | 1) => {
    const next = moveEnvironment(environments, index, delta);
    if (next === environments) return;
    void run(async () => {
      onChange(await client.reorder(projectId, next.map(({ id }) => id)));
      setStatus("Environment order saved.");
    }, "Environment order could not be saved.");
  };

  const save = (environment: EnvironmentView, input: EnvironmentInput) => run(async () => {
    const updated = await client.update(projectId, environment.id, input);
    onChange(environments.map((item) => item.id === environment.id ? updated : item));
    setEditingId(null);
    setStatus(`${updated.name} updated.`);
  }, "Environment could not be updated.");

  const remove = (environment: EnvironmentView) => run(async () => {
    const count = secretCounts[environment.id] ?? 0;
    try {
      await client.remove(projectId, environment.id, count > 0 || forceDeleteId === environment.id);
    } catch (reason) {
      if (reason instanceof EnvironmentConfirmationError) {
        setForceDeleteId(environment.id);
        throw new Error(`${reason.message} Confirm again to delete the environment together with its secrets.`);
      }
      throw reason;
    }
    onChange(environments.filter(({ id }) => id !== environment.id));
    setConfirmingId(null);
    setForceDeleteId(null);
    setStatus(count > 0 ? `${environment.name} deleted with ${count} secret${count === 1 ? "" : "s"}.` : `${environment.name} deleted.`);
  }, "Environment could not be deleted.");

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void run(async () => {
      const created = await client.create(projectId, { name: name.trim(), slug, protected: isProtected });
      onChange([...environments, created]);
      setName("");
      setSlug("");
      setSlugEdited(false);
      setIsProtected(false);
      setStatus(`${created.name} added.`);
    }, "Environment could not be created.");
  };

  return <div className="sheet-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
    <section className="editor-sheet environment-sheet" role="dialog" aria-modal="true" aria-label="Manage environments">
      <header>
        <div><span className="kicker">Project settings</span><h2>Environments</h2><p>This order drives the tabs and the diff matrix. Protected environments only accept writes from elevated roles.</p></div>
        <button type="button" aria-label="Close environment manager" onClick={onCancel}>×</button>
      </header>
      <div className="environment-list" role="list" aria-label="Environments in display order">
        {environments.map((environment, index) => editingId === environment.id
          ? <EnvironmentEditForm key={environment.id} environment={environment} busy={busy} onCancel={() => setEditingId(null)} onSave={(input) => void save(environment, input)} />
          : <div role="listitem" key={environment.id}>
            <div className="environment-identity">
              <strong>{environment.name}{environment.protected ? <b title="Protected environment">◆</b> : null}</strong>
              <code>{environment.slug}</code>
              <small>{secretCounts[environment.id] ?? 0} secret{(secretCounts[environment.id] ?? 0) === 1 ? "" : "s"}</small>
            </div>
            {permissions.manage ? <div className="environment-controls">
              <button type="button" aria-label={`Move ${environment.name} up`} disabled={busy || index === 0} onClick={() => move(index, -1)}>↑</button>
              <button type="button" aria-label={`Move ${environment.name} down`} disabled={busy || index === environments.length - 1} onClick={() => move(index, 1)}>↓</button>
              <button type="button" aria-label={`Edit ${environment.name}`} disabled={busy} onClick={() => { setEditingId(environment.id); setConfirmingId(null); setError(null); }}>Edit</button>
              {permissions.remove ? <button type="button" className="danger" aria-label={`Delete ${environment.name}`} disabled={busy || environments.length <= 1} onClick={() => { setConfirmingId(environment.id); setForceDeleteId(null); setError(null); }}>Delete</button> : null}
            </div> : null}
            {confirmingId === environment.id ? <div className="environment-confirm" role="alert">
              <span>Delete {environment.name}?{(secretCounts[environment.id] ?? 0) > 0 ? ` Its ${secretCounts[environment.id]} secret${secretCounts[environment.id] === 1 ? "" : "s"} will be deleted with it.` : ""}</span>
              <button type="button" disabled={busy} onClick={() => { setConfirmingId(null); setForceDeleteId(null); }}>Keep</button>
              <button type="button" className="danger" disabled={busy} onClick={() => void remove(environment)}>{forceDeleteId === environment.id ? "Delete with secrets" : "Delete environment"}</button>
            </div> : null}
          </div>)}
      </div>
      {permissions.manage ? <form className="environment-create" aria-label="Add environment" onSubmit={create}>
        <h3>Add an environment</h3>
        <label>Name<input name="name" value={name} required minLength={1} maxLength={80} placeholder="QA" onChange={(event) => { setName(event.target.value); if (!slugEdited) setSlug(suggestEnvironmentSlug(event.target.value)); }} /></label>
        <label>Slug<input name="slug" value={slug} required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={80} placeholder="qa" onChange={(event) => { setSlugEdited(true); setSlug(event.target.value); }} /></label>
        <label className="check-row"><input type="checkbox" checked={isProtected} onChange={(event) => setIsProtected(event.target.checked)} /> Protected · elevated writes only</label>
        <div className="form-actions"><button className="primary-button" type="submit" disabled={busy || name.trim() === "" || slug === ""}>{busy ? "Working…" : "Add environment"}</button></div>
      </form> : null}
      {error ? <p className="import-error" role="alert">{error}</p> : null}
      {status ? <p className="form-status success" role="status">{status}</p> : null}
      <footer><span>Deleting an environment also deletes the secrets inside it.</span><button className="secondary-button" type="button" onClick={onCancel}>Done</button></footer>
    </section>
  </div>;
}

function EnvironmentEditForm({ environment, busy, onCancel, onSave }: {
  environment: EnvironmentView;
  busy: boolean;
  onCancel: () => void;
  onSave: (input: EnvironmentInput) => void;
}): ReactNode {
  const [name, setName] = useState(environment.name);
  const [slug, setSlug] = useState(environment.slug);
  const [isProtected, setIsProtected] = useState(environment.protected);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSave({ name: name.trim(), slug, protected: isProtected });
  };
  return <form className="environment-form" aria-label={`Edit ${environment.name}`} onSubmit={submit}>
    <label>Name<input name="name" value={name} required minLength={1} maxLength={80} autoFocus onChange={(event) => setName(event.target.value)} /></label>
    <label>Slug<input name="slug" value={slug} required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={80} onChange={(event) => setSlug(event.target.value)} /></label>
    <label className="check-row"><input type="checkbox" checked={isProtected} onChange={(event) => setIsProtected(event.target.checked)} /> Protected · elevated writes only</label>
    <div className="form-actions"><button type="button" onClick={onCancel} disabled={busy}>Cancel</button><button type="submit" disabled={busy || name.trim() === "" || slug === ""}>{busy ? "Saving…" : "Save"}</button></div>
  </form>;
}
