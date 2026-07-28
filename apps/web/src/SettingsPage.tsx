import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { apiFetch, csrfToken } from "./session.js";
import { NavLink } from "react-router-dom";

export type SettingsRole = "owner" | "admin" | "member" | "read_only";

export interface SettingsProject {
  readonly id: string;
  readonly name: string;
}

export interface OrganizationSettingsView {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly retentionDays: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface MemberSettingsView {
  readonly userId: string;
  readonly email: string;
  readonly role: SettingsRole;
  readonly status: "invited" | "active" | "suspended";
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface InvitationSettingsView {
  readonly id: string;
  readonly email: string;
  readonly role: Exclude<SettingsRole, "owner">;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface ApiKeySettingsView {
  readonly id: string;
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly name: string;
  readonly prefix: string;
  readonly access: "read_only" | "read_write";
  readonly createdAt: string;
  readonly expiresAt: string | null;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
}

export interface TagSettingsView {
  readonly id: string;
  readonly name: string;
  readonly color: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface EnvironmentSettingsView {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
}

export interface SettingsClient {
  organization(): Promise<OrganizationSettingsView>;
  updateOrganization(input: { name: string; slug: string }): Promise<OrganizationSettingsView>;
  members(): Promise<readonly MemberSettingsView[]>;
  updateMember(userId: string, role: Exclude<SettingsRole, "owner">): Promise<MemberSettingsView>;
  removeMember(userId: string): Promise<MemberSettingsView>;
  invitations(): Promise<readonly InvitationSettingsView[]>;
  invite(input: { email: string; role: Exclude<SettingsRole, "owner"> }): Promise<{ email: string; role: string }>;
  revokeInvitation(id: string): Promise<InvitationSettingsView>;
  apiKeys(): Promise<readonly ApiKeySettingsView[]>;
  createApiKey(input: { name: string; access: "read_only" | "read_write"; projectId?: string | null; environmentId?: string | null; expiresAt?: string | null }): Promise<{ apiKey: ApiKeySettingsView; token: string }>;
  revokeApiKey(id: string): Promise<ApiKeySettingsView>;
  tags(): Promise<readonly TagSettingsView[]>;
  createTag(input: { name: string; color: string }): Promise<TagSettingsView>;
  updateTag(id: string, input: { name: string; color: string }): Promise<TagSettingsView>;
  deleteTag(id: string): Promise<TagSettingsView>;
  retention(): Promise<number>;
  updateRetention(days: number): Promise<number>;
  environments(projectId: string): Promise<readonly EnvironmentSettingsView[]>;
}

type RequestFunction = (input: string, init?: RequestInit) => Promise<Response>;

function browserCsrfToken(): string | null {
  if (typeof document === "undefined") return null;
  return csrfToken();
}

export function createSettingsClient(request: RequestFunction = (input, init) => fetch(input, init)): SettingsClient {
  const json = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const csrf = init?.method === undefined || init.method === "GET" ? null : browserCsrfToken();
    const response = await request(path, {
      credentials: "same-origin",
      ...init,
      headers: {
        "content-type": "application/json",
        ...(csrf === null ? {} : { "x-csrf-token": csrf }),
        ...init?.headers,
      },
    });
    const payload = await response.json().catch(() => null) as { data?: T; error?: { message?: string } } | null;
    if (!response.ok) throw new Error(payload?.error?.message ?? `Request failed (${response.status})`);
    if (payload?.data === undefined) throw new Error("Settings response was incomplete.");
    return payload.data;
  };
  return {
    organization: () => json("/api/v1/organization"),
    updateOrganization: (input) => json("/api/v1/organization", { method: "PATCH", body: JSON.stringify(input) }),
    members: () => json("/api/v1/members"),
    updateMember: (userId, role) => json(`/api/v1/members/${encodeURIComponent(userId)}`, { method: "PATCH", body: JSON.stringify({ role }) }),
    removeMember: (userId) => json(`/api/v1/members/${encodeURIComponent(userId)}`, { method: "DELETE" }),
    invitations: () => json("/api/v1/invitations"),
    invite: (input) => json("/api/v1/invitations", { method: "POST", body: JSON.stringify(input) }),
    revokeInvitation: (id) => json(`/api/v1/invitations/${encodeURIComponent(id)}`, { method: "DELETE" }),
    apiKeys: () => json("/api/v1/api-keys?limit=100"),
    createApiKey: (input) => json("/api/v1/api-keys", { method: "POST", body: JSON.stringify(input) }),
    revokeApiKey: (id) => json(`/api/v1/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
    tags: () => json("/api/v1/tags?limit=100"),
    createTag: (input) => json("/api/v1/tags", { method: "POST", body: JSON.stringify(input) }),
    updateTag: (id, input) => json(`/api/v1/tags/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(input) }),
    deleteTag: (id) => json(`/api/v1/tags/${encodeURIComponent(id)}`, { method: "DELETE" }),
    retention: async () => (await json<{ retentionDays: number }>("/api/v1/audit-settings")).retentionDays,
    updateRetention: async (retentionDays) => (await json<{ retentionDays: number }>("/api/v1/audit-settings", { method: "PATCH", body: JSON.stringify({ retentionDays }) })).retentionDays,
    environments: (projectId) => json(`/api/v1/projects/${encodeURIComponent(projectId)}/environments?limit=100`),
  };
}

const browserSettingsClient = createSettingsClient(apiFetch);

function when(value: string | null): string {
  return value === null ? "Never" : new Date(value).toLocaleString();
}

export function SettingsPage({ role, projects, client = browserSettingsClient }: {
  role: SettingsRole;
  projects: readonly SettingsProject[];
  client?: SettingsClient;
}): ReactNode {
  const [organization, setOrganization] = useState<OrganizationSettingsView | null>(null);
  const [orgDraft, setOrgDraft] = useState({ name: "", slug: "" });
  const [members, setMembers] = useState<readonly MemberSettingsView[]>([]);
  const [invitations, setInvitations] = useState<readonly InvitationSettingsView[]>([]);
  const [apiKeys, setApiKeys] = useState<readonly ApiKeySettingsView[]>([]);
  const [tags, setTags] = useState<readonly TagSettingsView[]>([]);
  const [retentionDays, setRetentionDays] = useState(90);
  const [scopeType, setScopeType] = useState<"organization" | "project" | "environment">("organization");
  const [scopeProject, setScopeProject] = useState(projects[0]?.id ?? "");
  const [scopeEnvironment, setScopeEnvironment] = useState("");
  const [scopeEnvironments, setScopeEnvironments] = useState<readonly EnvironmentSettingsView[]>([]);
  const [revealedToken, setRevealedToken] = useState<{ name: string; token: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const canAdminister = role === "owner" || role === "admin";

  const load = async () => {
    const [nextOrganization, nextMembers, nextInvitations, nextApiKeys, nextTags, nextRetention] = await Promise.all([
      client.organization(), client.members(), client.invitations(),
      canAdminister ? client.apiKeys() : Promise.resolve([]), client.tags(),
      canAdminister ? client.retention() : Promise.resolve(null),
    ]);
    setOrganization(nextOrganization);
    setOrgDraft({ name: nextOrganization.name, slug: nextOrganization.slug });
    setMembers(nextMembers);
    setInvitations(nextInvitations);
    setApiKeys(nextApiKeys);
    setTags(nextTags);
    setRetentionDays(nextRetention ?? nextOrganization.retentionDays);
  };

  useEffect(() => {
    setBusy(true);
    void load().catch((reason: unknown) => setNotice({ kind: "error", message: reason instanceof Error ? reason.message : "Settings could not be loaded." })).finally(() => setBusy(false));
  }, [client, canAdminister]);

  useEffect(() => {
    if (scopeType !== "environment" || scopeProject === "") { setScopeEnvironments([]); setScopeEnvironment(""); return; }
    void client.environments(scopeProject).then((rows) => {
      setScopeEnvironments(rows);
      setScopeEnvironment(rows[0]?.id ?? "");
    }).catch((reason: unknown) => setNotice({ kind: "error", message: reason instanceof Error ? reason.message : "Environments could not be loaded." }));
  }, [client, scopeProject, scopeType]);

  const perform = async (action: () => Promise<void>, message: string) => {
    setBusy(true);
    setNotice(null);
    try { await action(); setNotice({ kind: "success", message }); }
    catch (reason) { setNotice({ kind: "error", message: reason instanceof Error ? reason.message : "The settings change failed." }); }
    finally { setBusy(false); }
  };

  const saveOrganization = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void perform(async () => { setOrganization(await client.updateOrganization(orgDraft)); }, "Organization profile updated.");
  };
  const invite = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    void perform(async () => {
      await client.invite({ email: String(form.get("email") ?? ""), role: String(form.get("role") ?? "member") as Exclude<SettingsRole, "owner"> });
      setInvitations(await client.invitations());
      formElement.reset();
    }, "Invitation sent.");
  };
  const createKey = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const expiresAt = String(form.get("expiresAt") ?? "");
    void perform(async () => {
      const created = await client.createApiKey({
        name: String(form.get("name") ?? ""),
        access: String(form.get("access") ?? "read_only") as "read_only" | "read_write",
        ...(scopeType === "organization" ? {} : { projectId: scopeProject }),
        ...(scopeType === "environment" ? { environmentId: scopeEnvironment } : {}),
        expiresAt: expiresAt === "" ? null : new Date(expiresAt).toISOString(),
      });
      setRevealedToken({ name: created.apiKey.name, token: created.token });
      setApiKeys(await client.apiKeys());
      formElement.reset();
    }, "API key created. Copy it before dismissing the reveal.");
  };
  const createTag = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    void perform(async () => {
      await client.createTag({ name: String(form.get("name") ?? ""), color: String(form.get("color") ?? "#7C3AED") });
      setTags(await client.tags());
      formElement.reset();
    }, "Tag created.");
  };

  return <div className="settings-page page-stack">
    <header className="page-header"><div><span>Workspace</span><h1>Settings</h1><p>Manage people, machine access, taxonomy, organization policy, and data movement from one governed surface.</p></div></header>
    {notice ? <p className={`settings-notice ${notice.kind}`} role="status">{notice.message}<button type="button" onClick={() => setNotice(null)} aria-label="Dismiss settings notice">×</button></p> : null}
    {!canAdminister ? <section className="settings-readonly"><strong>Read-only settings view</strong><p>Your role can inspect members, tags, organization policy, and import/export entry points. Owner or administrator access is required to change them.</p></section> : null}

    <section className="settings-card settings-members" aria-labelledby="members-heading">
      <SettingsHeading id="members-heading" eyebrow="People" title="Members & invitations" copy="Roles are enforced centrally across the API and web workspace." />
      {canAdminister ? <form className="settings-inline-form" onSubmit={invite} aria-label="Invite member"><label>Email<input name="email" type="email" required placeholder="teammate@example.com" /></label><label>Role<select name="role" defaultValue="member"><option value="admin">Admin</option><option value="member">Member</option><option value="read_only">Read-only</option></select></label><button className="primary-button" disabled={busy}>Send invite</button></form> : null}
      <div className="settings-list member-list">
        {members.map((member) => <article key={member.userId}><div className="settings-identity"><span>{member.email.slice(0, 1).toUpperCase()}</span><div><strong>{member.email}</strong><small>Joined {new Date(member.createdAt).toLocaleDateString()}</small></div></div><div className="settings-row-actions"><select aria-label={`Role for ${member.email}`} value={member.role} disabled={!canAdminister || member.role === "owner" || (role === "admin" && member.role === "admin") || busy} onChange={(event) => void perform(async () => { const updated = await client.updateMember(member.userId, event.target.value as Exclude<SettingsRole, "owner">); setMembers((rows) => rows.map((row) => row.userId === updated.userId ? updated : row)); }, `Role updated for ${member.email}.`)}><option value="owner">Owner</option><option value="admin" disabled={role === "admin"}>Admin</option><option value="member">Member</option><option value="read_only">Read-only</option></select>{canAdminister && member.role !== "owner" && !(role === "admin" && member.role === "admin") ? <button type="button" className="danger-link" disabled={busy} onClick={() => void perform(async () => { await client.removeMember(member.userId); setMembers((rows) => rows.filter(({ userId }) => userId !== member.userId)); }, `${member.email} removed.`)}>Remove</button> : null}</div></article>)}
        {members.length === 0 ? <p className="settings-empty">{busy ? "Loading members…" : "No active members found."}</p> : null}
      </div>
      {invitations.length > 0 ? <div className="pending-invites"><h3>Pending invitations</h3>{invitations.map((invitation) => <article key={invitation.id}><span><strong>{invitation.email}</strong><small>{invitation.role.replace("_", " ")} · expires {new Date(invitation.expiresAt).toLocaleDateString()}</small></span>{canAdminister ? <button type="button" disabled={busy} onClick={() => void perform(async () => { await client.revokeInvitation(invitation.id); setInvitations((rows) => rows.filter(({ id }) => id !== invitation.id)); }, "Invitation revoked.")}>Revoke</button> : null}</article>)}</div> : null}
    </section>

    <section className="settings-card settings-api-keys" aria-labelledby="keys-heading">
      <SettingsHeading id="keys-heading" eyebrow="Machine access" title="API keys" copy="Create least-privilege service credentials. Plaintext is revealed exactly once." />
      {revealedToken ? <div className="one-time-token" role="alert"><strong>Copy {revealedToken.name} now</strong><code>{revealedToken.token}</code><button type="button" onClick={() => setRevealedToken(null)}>I saved this key</button></div> : null}
      {canAdminister ? <form className="settings-key-form" onSubmit={createKey} aria-label="Create API key"><label>Name<input name="name" required maxLength={120} placeholder="Production deploy" /></label><label>Access<select name="access" defaultValue="read_only"><option value="read_only">Read-only</option><option value="read_write">Read-write</option></select></label><label>Scope<select value={scopeType} onChange={(event) => setScopeType(event.target.value as typeof scopeType)}><option value="organization">Organization</option><option value="project">Project</option><option value="environment">Project + environment</option></select></label>{scopeType !== "organization" ? <label>Project<select value={scopeProject} required onChange={(event) => setScopeProject(event.target.value)}>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label> : null}{scopeType === "environment" ? <label>Environment<select value={scopeEnvironment} required onChange={(event) => setScopeEnvironment(event.target.value)}>{scopeEnvironments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}</select></label> : null}<label>Expires <span>optional</span><input name="expiresAt" type="datetime-local" /></label><button className="primary-button" disabled={busy || (scopeType !== "organization" && scopeProject === "") || (scopeType === "environment" && scopeEnvironment === "")}>Create key</button></form> : null}
      <div className="settings-list key-list">{apiKeys.map((key) => <article key={key.id} className={key.revokedAt === null ? "" : "revoked"}><div><strong>{key.name}</strong><code>{key.prefix}…</code></div><span>{key.access.replace("_", " ")} · {key.environmentId !== null ? "environment" : key.projectId !== null ? "project" : "organization"}</span><small>Last used: {when(key.lastUsedAt)}</small>{canAdminister && key.revokedAt === null ? <button className="danger-link" type="button" disabled={busy} onClick={() => void perform(async () => { const revoked = await client.revokeApiKey(key.id); setApiKeys((rows) => rows.map((row) => row.id === revoked.id ? revoked : row)); }, `${key.name} revoked.`)}>Revoke</button> : <em>{key.revokedAt === null ? "Active" : "Revoked"}</em>}</article>)}{apiKeys.length === 0 ? <p className="settings-empty">{canAdminister ? "No API keys yet." : "API key inventory is restricted to owners and administrators."}</p> : null}</div>
    </section>

    <section className="settings-card settings-tags" aria-labelledby="tags-heading">
      <SettingsHeading id="tags-heading" eyebrow="Taxonomy" title="Tag registry" copy="Keep project and secret classification consistent across the organization." />
      {canAdminister ? <form className="settings-inline-form tag-create" onSubmit={createTag} aria-label="Create tag"><label>Name<input name="name" required maxLength={80} placeholder="compliance" /></label><label>Color<input name="color" type="color" defaultValue="#7C3AED" /></label><button className="primary-button" disabled={busy}>Create tag</button></form> : null}
      <div className="tag-registry">{tags.map((tag) => <form key={tag.id} onSubmit={(event) => { event.preventDefault(); const form = new FormData(event.currentTarget); void perform(async () => { const updated = await client.updateTag(tag.id, { name: String(form.get("name") ?? ""), color: String(form.get("color") ?? tag.color) }); setTags((rows) => rows.map((row) => row.id === updated.id ? updated : row)); }, `#${tag.name} updated.`); }}><i style={{ background: tag.color }} /><input aria-label={`Tag name ${tag.name}`} name="name" defaultValue={tag.name} disabled={!canAdminister} /><input aria-label={`Tag color ${tag.name}`} name="color" type="color" defaultValue={tag.color} disabled={!canAdminister} />{canAdminister ? <><button type="submit" disabled={busy}>Save</button><button type="button" className="danger-link" disabled={busy} onClick={() => void perform(async () => { await client.deleteTag(tag.id); setTags((rows) => rows.filter(({ id }) => id !== tag.id)); }, `#${tag.name} deleted.`)}>Delete</button></> : null}</form>)}{tags.length === 0 ? <p className="settings-empty">No organization tags yet.</p> : null}</div>
    </section>

    <section className="settings-card settings-organization" aria-labelledby="organization-heading">
      <SettingsHeading id="organization-heading" eyebrow="Organization" title="Profile & retention" copy="Stable organization identity with a compliance-ready audit retention policy." />
      <div className="settings-policy-grid"><form onSubmit={saveOrganization} aria-label="Organization profile"><label>Name<input value={orgDraft.name} required maxLength={120} disabled={!canAdminister} onChange={(event) => setOrgDraft((draft) => ({ ...draft, name: event.target.value }))} /></label><label>Slug<input value={orgDraft.slug} required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={80} disabled={!canAdminister} onChange={(event) => setOrgDraft((draft) => ({ ...draft, slug: event.target.value }))} /></label>{canAdminister ? <button className="primary-button" disabled={busy || organization === null}>Save profile</button> : null}</form><form aria-label="Audit retention" onSubmit={(event) => { event.preventDefault(); void perform(async () => setRetentionDays(await client.updateRetention(retentionDays)), "Audit retention policy updated."); }}><label>Retain audit events<input type="number" min={1} max={3650} value={retentionDays} disabled={!canAdminister} onChange={(event) => setRetentionDays(Number(event.target.value))} /><span>days</span></label><p>Applies to organization audit history and compliance exports.</p>{canAdminister ? <button className="primary-button" disabled={busy}>Save retention</button> : null}</form></div>
    </section>

    <section className="settings-card settings-transfer" aria-labelledby="transfer-heading">
      <SettingsHeading id="transfer-heading" eyebrow="Data movement" title="Import & export" copy="Open a project to preview imports or download audited .env, JSON, and shell exports." />
      <div className="transfer-projects">{projects.map((project) => <NavLink key={project.id} to={`/app/projects/${project.id}`}><span><strong>{project.name}</strong><small>Import, export, and environment tools</small></span><b>Open project →</b></NavLink>)}{projects.length === 0 ? <p className="settings-empty">Create a project before importing or exporting secrets.</p> : null}</div>
    </section>
  </div>;
}

function SettingsHeading({ id, eyebrow, title, copy }: { id: string; eyebrow: string; title: string; copy: string }): ReactNode {
  return <header className="settings-heading"><div><span>{eyebrow}</span><h2 id={id}>{title}</h2></div><p>{copy}</p></header>;
}
