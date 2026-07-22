import {
  type FormEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export interface EnvironmentView {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly protected: boolean;
}

export interface SecretView {
  readonly id: string;
  readonly environmentId: string;
  readonly key: string;
  readonly notes: string | null;
  readonly currentVersion: number;
  readonly updatedAt: string;
  readonly tags: readonly string[];
  readonly pending?: boolean;
  readonly conflict?: string;
}

export interface SecretVersionView {
  readonly version: number;
  readonly authorUserId: string | null;
  readonly changeNote: string | null;
  readonly encryptionKeyVersion: number;
  readonly createdAt: string;
  readonly current: boolean;
}

export interface BulkSecretInput {
  readonly key: string;
  readonly value: string;
  readonly allowNonConformingKey?: boolean;
}

export interface BulkParseResult {
  readonly secrets: readonly BulkSecretInput[];
  readonly errors: readonly string[];
}

interface ApiSecretMetadata {
  readonly id: string;
  readonly environmentId: string;
  readonly key: string;
  readonly notes: string | null;
  readonly currentVersion: number;
  readonly updatedAt: string;
}

interface ApiSecretValue extends ApiSecretMetadata {
  readonly value: string;
}

type RequestFunction = (input: string, init?: RequestInit) => Promise<Response>;

export class SecretConflictError extends Error {
  constructor(message = "This secret changed on the server. Review the latest version and try again.") {
    super(message);
    this.name = "SecretConflictError";
  }
}

export interface SecretClient {
  list(projectId: string, environmentId: string): Promise<readonly ApiSecretMetadata[]>;
  reveal(secretId: string): Promise<ApiSecretValue>;
  create(projectId: string, environmentId: string, input: BulkSecretInput & { notes?: string | null }): Promise<ApiSecretMetadata>;
  update(secretId: string, expectedVersion: number, input: { value: string; notes?: string | null; changeNote?: string }): Promise<ApiSecretMetadata>;
  bulkSet(projectId: string, environmentId: string, secrets: readonly BulkSecretInput[]): Promise<readonly ApiSecretMetadata[]>;
  versions(secretId: string): Promise<readonly SecretVersionView[]>;
}

export function isConventionalSecretKey(key: string): boolean {
  return /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(key.trim());
}

export function parseBulkSecrets(source: string): BulkParseResult {
  const secrets: BulkSecretInput[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const [index, rawLine] of source.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const equals = line.indexOf("=");
    if (equals < 1) { errors.push(`Line ${index + 1}: expected KEY=value`); continue; }
    const key = line.slice(0, equals).trim();
    if (key === "" || /[\s=]/.test(key)) { errors.push(`Line ${index + 1}: invalid key`); continue; }
    if (seen.has(key)) { errors.push(`Line ${index + 1}: duplicate key ${key}`); continue; }
    seen.add(key);
    let value = line.slice(equals + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    } else if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    }
    secrets.push({ key, value, ...(!isConventionalSecretKey(key) ? { allowNonConformingKey: true } : {}) });
  }
  if (secrets.length > 100) errors.push("Bulk writes are limited to 100 secrets.");
  return { secrets: secrets.slice(0, 100), errors };
}

export function filterSecretRows(
  secrets: readonly SecretView[],
  query: string,
  activeTag: string | null,
): readonly SecretView[] {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  return secrets.filter((secret) => {
    if (activeTag !== null && !secret.tags.includes(activeTag)) return false;
    const search = `${secret.key} ${secret.notes ?? ""} ${secret.tags.join(" ")}`.toLocaleLowerCase();
    return terms.every((term) => search.includes(term));
  });
}

export function createSecretClient(request: RequestFunction = (input, init) => fetch(input, init)): SecretClient {
  const json = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await request(path, {
      credentials: "same-origin",
      ...init,
      headers: { "content-type": "application/json", ...init?.headers },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null) as { error?: { message?: string } } | null;
      const message = payload?.error?.message ?? `Request failed (${response.status})`;
      if (response.status === 409 || response.status === 412) throw new SecretConflictError(message);
      throw new Error(message);
    }
    return (await response.json() as { data: T }).data;
  };
  return {
    list: (projectId, environmentId) => json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets`),
    reveal: (secretId) => json(`/api/v1/secrets/${encodeURIComponent(secretId)}`),
    create: (projectId, environmentId, input) => json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets`, { method: "POST", body: JSON.stringify(input) }),
    update: (secretId, expectedVersion, input) => json(`/api/v1/secrets/${encodeURIComponent(secretId)}`, { method: "PATCH", headers: { "if-match": `\"${expectedVersion}\"` }, body: JSON.stringify(input) }),
    bulkSet: (projectId, environmentId, secrets) => json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(environmentId)}/secrets/bulk`, { method: "POST", body: JSON.stringify({ secrets }) }),
    versions: (secretId) => json(`/api/v1/secrets/${encodeURIComponent(secretId)}/versions?limit=100`),
  };
}

const browserSecretClient = createSecretClient();

export const demoEnvironments: readonly EnvironmentView[] = [
  { id: "development", name: "Development", slug: "development", protected: false },
  { id: "staging", name: "Staging", slug: "staging", protected: false },
  { id: "production", name: "Production", slug: "production", protected: true },
];

export const demoSecretRows: readonly SecretView[] = [
  { id: "0d125db6-1017-4d6e-aa37-e201b8d6ac50", environmentId: "development", key: "DATABASE_URL", notes: "Primary application database", currentVersion: 7, updatedAt: "2026-07-22T02:14:00.000Z", tags: ["database", "critical"] },
  { id: "a37fe76d-2784-4514-846e-b0a8c06d8f59", environmentId: "development", key: "STRIPE_SECRET_KEY", notes: "Billing service credential", currentVersion: 3, updatedAt: "2026-07-21T08:40:00.000Z", tags: ["third-party"] },
  { id: "5b62f475-cda7-40d7-8977-4091d65cf759", environmentId: "development", key: "REDIS_URL", notes: "Shared cache", currentVersion: 2, updatedAt: "2026-07-20T11:02:00.000Z", tags: ["database"] },
  { id: "02d00455-ee4e-408d-aec0-66e3fb6a8538", environmentId: "development", key: "SENTRY_DSN", notes: null, currentVersion: 1, updatedAt: "2026-07-18T01:20:00.000Z", tags: ["observability", "third-party"] },
  { id: "cc90e201-4078-41d6-bc53-c295f47cc79b", environmentId: "staging", key: "DATABASE_URL", notes: "Staging database", currentVersion: 5, updatedAt: "2026-07-21T03:10:00.000Z", tags: ["database", "critical"] },
  { id: "e25be465-45ca-4ca9-b1f8-d80186bc2cea", environmentId: "production", key: "DATABASE_URL", notes: "Production database", currentVersion: 11, updatedAt: "2026-07-22T01:05:00.000Z", tags: ["database", "critical"] },
];

function metadataToView(metadata: ApiSecretMetadata, tags: readonly string[] = []): SecretView {
  return { ...metadata, tags };
}

export function SecretWorkspace({
  projectId,
  projectName,
  environments = demoEnvironments,
  initialSecrets = demoSecretRows,
  client = browserSecretClient,
}: {
  projectId: string;
  projectName: string;
  environments?: readonly EnvironmentView[];
  initialSecrets?: readonly SecretView[];
  client?: SecretClient;
}): ReactNode {
  const [activeEnvironmentId, setActiveEnvironmentId] = useState(environments[0]?.id ?? "");
  const [secrets, setSecrets] = useState<readonly SecretView[]>(initialSecrets);
  const [query, setQuery] = useState("");
  const [activeTag, setActiveTag] = useState<string | null>(null);
  const [editor, setEditor] = useState<{ mode: "add" | "edit"; secret?: SecretView } | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [historySecret, setHistorySecret] = useState<SecretView | null>(null);
  const [revealed, setRevealed] = useState<Readonly<Record<string, string>>>({});
  const [notice, setNotice] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const remaskTimers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const environment = environments.find(({ id }) => id === activeEnvironmentId) ?? environments[0];
  const environmentSecrets = secrets.filter(({ environmentId }) => environmentId === activeEnvironmentId);
  const tags = [...new Set(environmentSecrets.flatMap(({ tags: rowTags }) => rowTags))].sort();
  const visibleSecrets = useMemo(
    () => filterSecretRows(environmentSecrets, query, activeTag),
    [environmentSecrets, query, activeTag],
  );

  useEffect(() => () => {
    for (const timer of remaskTimers.current.values()) clearTimeout(timer);
    remaskTimers.current.clear();
  }, []);

  const remask = (secretId: string) => {
    const timer = remaskTimers.current.get(secretId);
    if (timer !== undefined) clearTimeout(timer);
    remaskTimers.current.delete(secretId);
    setRevealed((current) => {
      const next = { ...current };
      delete next[secretId];
      return next;
    });
  };

  const reveal = async (secret: SecretView): Promise<string | null> => {
    if (revealed[secret.id] !== undefined) { remask(secret.id); return null; }
    try {
      const result = await client.reveal(secret.id);
      setRevealed((current) => ({ ...current, [secret.id]: result.value }));
      const existing = remaskTimers.current.get(secret.id);
      if (existing !== undefined) clearTimeout(existing);
      remaskTimers.current.set(secret.id, setTimeout(() => remask(secret.id), 15_000));
      return result.value;
    } catch (error) {
      setNotice({ kind: "error", message: error instanceof Error ? error.message : "Secret could not be revealed." });
      return null;
    }
  };

  const copy = async (secret: SecretView) => {
    try {
      const result = revealed[secret.id] ?? (await client.reveal(secret.id)).value;
      await navigator.clipboard.writeText(result);
      setNotice({ kind: "success", message: `${secret.key} copied. Clipboard contents were not retained by Himitsu.` });
    } catch (error) {
      setNotice({ kind: "error", message: error instanceof Error ? error.message : "Secret could not be copied." });
    }
  };

  const save = async (values: { key: string; value: string; notes: string; allowNonConformingKey: boolean; changeNote: string }) => {
    if (environment === undefined) return;
    setNotice(null);
    if (editor?.mode === "edit" && editor.secret !== undefined) {
      const before = editor.secret;
      const optimistic: SecretView = {
        id: before.id,
        environmentId: before.environmentId,
        key: before.key,
        notes: values.notes || null,
        currentVersion: before.currentVersion + 1,
        updatedAt: new Date().toISOString(),
        tags: before.tags,
        pending: true,
      };
      setSecrets((current) => current.map((row) => row.id === before.id ? optimistic : row));
      setEditor(null);
      remask(before.id);
      try {
        const saved = await client.update(before.id, before.currentVersion, {
          value: values.value,
          notes: values.notes || null,
          ...(values.changeNote ? { changeNote: values.changeNote } : {}),
        });
        setSecrets((current) => current.map((row) => row.id === before.id ? metadataToView(saved, before.tags) : row));
        setNotice({ kind: "success", message: `${before.key} updated.` });
      } catch (error) {
        const message = error instanceof SecretConflictError ? error.message : error instanceof Error ? error.message : "Update failed.";
        setSecrets((current) => current.map((row) => row.id === before.id ? { ...before, conflict: message } : row));
        setNotice({ kind: "error", message: `${before.key} was restored locally. ${message}` });
      }
      return;
    }
    const temporaryId = `pending-${crypto.randomUUID()}`;
    const temporary: SecretView = { id: temporaryId, environmentId: environment.id, key: values.key.trim(), notes: values.notes || null, currentVersion: 1, updatedAt: new Date().toISOString(), tags: [], pending: true };
    setSecrets((current) => [...current, temporary]);
    setEditor(null);
    try {
      const saved = await client.create(projectId, environment.id, { key: values.key, value: values.value, notes: values.notes || null, ...(values.allowNonConformingKey ? { allowNonConformingKey: true } : {}) });
      setSecrets((current) => current.map((row) => row.id === temporaryId ? metadataToView(saved) : row));
      setNotice({ kind: "success", message: `${saved.key} created.` });
    } catch (error) {
      setSecrets((current) => current.filter(({ id }) => id !== temporaryId));
      setNotice({ kind: "error", message: error instanceof Error ? error.message : "Secret could not be created." });
    }
  };

  const saveBulk = async (input: readonly BulkSecretInput[]) => {
    if (environment === undefined) return;
    setNotice(null);
    try {
      const saved = await client.bulkSet(projectId, environment.id, input);
      setSecrets((current) => {
        const other = current.filter(({ environmentId }) => environmentId !== environment.id);
        const existing = new Map(current.filter(({ environmentId }) => environmentId === environment.id).map((row) => [row.key, row]));
        return [...other, ...saved.map((row) => metadataToView(row, existing.get(row.key)?.tags))];
      });
      setBulkOpen(false);
      setNotice({ kind: "success", message: `${saved.length} secrets saved in one encrypted batch.` });
    } catch (error) {
      setNotice({ kind: "error", message: error instanceof Error ? error.message : "Bulk write failed; no optimistic rows were retained." });
    }
  };

  return (
    <div className="secret-workspace page-stack">
      <header className="project-heading">
        <div><a href="/app/projects">Projects</a><span>/</span><span>{projectName}</span></div>
        <span className="sync-state"><i /> encrypted workspace</span>
      </header>
      <section className="secret-hero">
        <div><span className="kicker">Project vault</span><h1>{projectName}</h1><p>Reveal only what you need. Values automatically return to a masked state after 15 seconds.</p></div>
        <div className="secret-actions"><button className="secondary-button" type="button" onClick={() => setBulkOpen(true)}>Bulk paste</button><button className="primary-button" type="button" onClick={() => setEditor({ mode: "add" })}>＋ Add secret</button></div>
      </section>
      <nav className="environment-tabs" aria-label="Project environments">
        {environments.map((item) => <button key={item.id} type="button" className={item.id === activeEnvironmentId ? "active" : ""} onClick={() => { setActiveEnvironmentId(item.id); setActiveTag(null); }}><span>{item.name}</span><small>{secrets.filter(({ environmentId }) => environmentId === item.id).length}</small>{item.protected ? <b title="Protected environment">◆</b> : null}</button>)}
      </nav>
      <section className="secret-panel">
        <header className="secret-toolbar">
          <label className="secret-search"><span aria-hidden="true">⌕</span><span className="sr-only">Search secrets</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search keys, notes, or tags" /></label>
          <div className="tag-filters" aria-label="Filter by tag"><button type="button" className={activeTag === null ? "active" : ""} onClick={() => setActiveTag(null)}>All</button>{tags.map((tag) => <button key={tag} type="button" className={activeTag === tag ? "active" : ""} onClick={() => setActiveTag(tag)}>#{tag}</button>)}</div>
          <span className="row-count">{visibleSecrets.length} / {environmentSecrets.length}</span>
        </header>
        {notice ? <p className={`workspace-notice ${notice.kind}`} role="status">{notice.message}<button type="button" aria-label="Dismiss notification" onClick={() => setNotice(null)}>×</button></p> : null}
        {editor ? <SecretEditor mode={editor.mode} {...(editor.secret === undefined ? {} : { secret: editor.secret })} onCancel={() => setEditor(null)} onSave={save} /> : null}
        <div className="secret-table" role="table" aria-label={`${environment?.name ?? "Environment"} secrets`}>
          <div className="secret-table-head" role="row"><span role="columnheader">Key</span><span role="columnheader">Encrypted value</span><span role="columnheader">Tags</span><span role="columnheader">Version</span><span role="columnheader" className="sr-only">Actions</span></div>
          {visibleSecrets.map((secret) => (
            <div className={`secret-row${secret.pending ? " pending" : ""}${secret.conflict ? " conflicted" : ""}`} role="row" key={secret.id}>
              <div className="secret-identity" role="cell"><strong>{secret.key}</strong><small>{secret.notes ?? "No note"}</small>{secret.conflict ? <em>{secret.conflict}</em> : null}</div>
              <button className={revealed[secret.id] === undefined ? "masked-value" : "masked-value revealed"} role="cell" type="button" aria-label={`${revealed[secret.id] === undefined ? "Reveal" : "Mask"} ${secret.key}`} onClick={() => void reveal(secret)}><code>{revealed[secret.id] ?? "••••••••••••••••"}</code><span>{revealed[secret.id] === undefined ? "reveal" : "mask"}</span></button>
              <div className="row-tags" role="cell">{secret.tags.length > 0 ? secret.tags.map((tag) => <button type="button" key={tag} onClick={() => setActiveTag(tag)}>#{tag}</button>) : <span>—</span>}</div>
              <button className="version-button" role="cell" type="button" onClick={() => setHistorySecret(secret)}>v{secret.currentVersion}</button>
              <div className="row-actions" role="cell"><button type="button" aria-label={`Copy ${secret.key}`} title="Copy value" onClick={() => void copy(secret)}>⧉</button><button type="button" aria-label={`Edit ${secret.key}`} title="Edit secret" onClick={() => setEditor({ mode: "edit", secret })}>✎</button></div>
            </div>
          ))}
          {visibleSecrets.length === 0 ? <div className="secret-empty"><span>∅</span><strong>No matching secrets</strong><p>Clear the search or tag filter, or add a secret to this environment.</p></div> : null}
        </div>
        <footer className="secret-panel-foot"><span><i /> Values are encrypted at rest and masked by default</span><span>{environment?.protected ? "Protected environment · elevated writes only" : "Standard write policy"}</span></footer>
      </section>
      {bulkOpen ? <BulkPaste onCancel={() => setBulkOpen(false)} onSave={saveBulk} /> : null}
      {historySecret ? <VersionDrawer secret={historySecret} client={client} onClose={() => setHistorySecret(null)} /> : null}
    </div>
  );
}

function SecretEditor({ mode, secret, onCancel, onSave }: {
  mode: "add" | "edit";
  secret?: SecretView;
  onCancel: () => void;
  onSave: (values: { key: string; value: string; notes: string; allowNonConformingKey: boolean; changeNote: string }) => Promise<void>;
}): ReactNode {
  const [key, setKey] = useState(secret?.key ?? "");
  const [allowNonConformingKey, setAllowNonConformingKey] = useState(false);
  const conventional = isConventionalSecretKey(key);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void onSave({ key, value: String(data.get("value") ?? ""), notes: String(data.get("notes") ?? ""), changeNote: String(data.get("changeNote") ?? ""), allowNonConformingKey });
  };
  return <form className="editor-sheet inline-secret-editor" aria-label={`${mode === "add" ? "Add" : "Edit"} secret`} onSubmit={submit}><header><div><span className="kicker">{mode === "add" ? "New encrypted value" : `Version ${secret?.currentVersion ?? ""}`}</span><h2>{mode === "add" ? "Add a secret" : `Update ${secret?.key ?? "secret"}`}</h2></div><button type="button" aria-label="Close editor" onClick={onCancel}>×</button></header><label>Key<input name="key" value={key} disabled={mode === "edit"} onChange={(event) => setKey(event.target.value)} required maxLength={255} autoFocus={mode === "add"} /><small className={conventional || key === "" ? "key-hint" : "key-hint warning"}>{conventional || key === "" ? "Use UPPERCASE_SNAKE_CASE, for example DATABASE_URL." : "This key does not follow UPPERCASE_SNAKE_CASE."}</small></label>{!conventional && key !== "" && mode === "add" ? <label className="check-row"><input type="checkbox" checked={allowNonConformingKey} onChange={(event) => setAllowNonConformingKey(event.target.checked)} /> Keep this non-standard key</label> : null}<label>{mode === "add" ? "Value" : "Replacement value"}<textarea name="value" required rows={5} spellCheck={false} autoComplete="off" placeholder="Secret value (never shown after save)" /></label><label>Note <span>optional</span><input name="notes" defaultValue={secret?.notes ?? ""} maxLength={4000} placeholder="What uses this secret?" /></label>{mode === "edit" ? <label>Change note <span>optional</span><input name="changeNote" maxLength={1000} placeholder="Why is this value changing?" /></label> : null}<footer><button className="secondary-button" type="button" onClick={onCancel}>Cancel</button><button className="primary-button" type="submit" disabled={key.trim() === "" || (!conventional && !allowNonConformingKey && mode === "add")}>{mode === "add" ? "Encrypt & save" : "Create new version"}</button></footer></form>;
}

function BulkPaste({ onCancel, onSave }: { onCancel: () => void; onSave: (input: readonly BulkSecretInput[]) => Promise<void> }): ReactNode {
  const [source, setSource] = useState("");
  const parsed = useMemo(() => parseBulkSecrets(source), [source]);
  return <div className="sheet-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}><section className="editor-sheet bulk-sheet" role="dialog" aria-modal="true" aria-label="Bulk paste secrets"><header><div><span className="kicker">Atomic batch</span><h2>Bulk paste</h2></div><button type="button" aria-label="Close bulk paste" onClick={onCancel}>×</button></header><label>Dotenv-style values<textarea value={source} onChange={(event) => setSource(event.target.value)} rows={12} spellCheck={false} placeholder={'DATABASE_URL="postgres://…"\nREDIS_URL=redis://…'} autoFocus /></label><div className="bulk-preview"><strong>{parsed.secrets.length} ready</strong><span>{parsed.secrets.filter(({ allowNonConformingKey }) => allowNonConformingKey).length} key overrides</span>{parsed.errors.map((error) => <em key={error}>{error}</em>)}</div><footer><button className="secondary-button" type="button" onClick={onCancel}>Cancel</button><button className="primary-button" type="button" disabled={parsed.secrets.length === 0 || parsed.errors.length > 0} onClick={() => void onSave(parsed.secrets)}>Review & save {parsed.secrets.length}</button></footer></section></div>;
}

function VersionDrawer({ secret, client, onClose }: { secret: SecretView; client: SecretClient; onClose: () => void }): ReactNode {
  const [versions, setVersions] = useState<readonly SecretVersionView[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    void client.versions(secret.id).then((result) => { if (active) setVersions(result); }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "History could not be loaded."); });
    return () => { active = false; };
  }, [client, secret.id]);
  return <div className="drawer-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><aside className="version-drawer" role="dialog" aria-modal="true" aria-label={`${secret.key} version history`}><header><div><span className="kicker">Immutable history</span><h2>{secret.key}</h2><p>Version metadata is visible; historical plaintext remains sealed.</p></div><button type="button" aria-label="Close version history" onClick={onClose}>×</button></header><div className="version-timeline">{error ? <p className="drawer-error">{error}</p> : null}{versions.length === 0 && error === null ? <p className="drawer-loading">Loading encrypted history…</p> : versions.map((version) => <article key={version.version} className={version.current ? "current" : ""}><i /><div><strong>Version {version.version}{version.current ? <span>current</span> : null}</strong><p>{version.changeNote ?? "No change note"}</p><small>{new Date(version.createdAt).toLocaleString()} · key v{version.encryptionKeyVersion}</small></div></article>)}</div><footer><span>{secret.currentVersion} immutable version{secret.currentVersion === 1 ? "" : "s"}</span><button className="secondary-button" type="button" onClick={onClose}>Done</button></footer></aside></div>;
}
