import { Select } from "./Select.js";
import {
  type FormEvent,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useNavigate,
  useOutletContext,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { SecretWorkspace, type EnvironmentView } from "./SecretWorkspace.js";
import { AuditPage } from "./AuditPage.js";
import { SettingsPage } from "./SettingsPage.js";
import { BUILD_LABEL } from "./version.js";
import {
  ApiRequestError,
  acceptInvitation,
  apiFetch,
  confirmPasswordReset,
  createOrganization,
  fetchSession,
  login,
  logout,
  requestPasswordReset,
  resendVerification,
  signup,
  switchOrganization,
  verifyEmail,
  type RequestFunction,
  type SessionOrganization,
  type SessionView,
} from "./session.js";

export interface ProjectQuickLink {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly environments: readonly string[];
  readonly tags: readonly string[];
}

export interface CommandItem {
  readonly id: string;
  readonly label: string;
  readonly eyebrow: string;
  readonly to: string;
  readonly search: string;
}

export type AuthMode = "login" | "signup" | "password-reset";

export function filterProjectLinks(projects: readonly ProjectQuickLink[], query: string, activeTag: string | null): readonly ProjectQuickLink[] {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  return projects.filter((project) => {
    if (activeTag !== null && !project.tags.includes(activeTag)) return false;
    const search = `${project.name} ${project.slug} ${project.tags.join(" ")}`.toLocaleLowerCase();
    return terms.every((term) => search.includes(term));
  });
}

export function filterCommandItems(items: readonly CommandItem[], query: string): readonly CommandItem[] {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return items;
  return items.filter(({ search }) => terms.every((term) => search.includes(term)));
}

export function suggestSlug(value: string): string {
  return value.trim().toLocaleLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

export function validateAuthForm(
  mode: AuthMode,
  values: { email: string; password?: string; confirmPassword?: string },
): string | null {
  const email = values.email.trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return "Enter a valid email address.";
  if (mode === "password-reset") return null;
  if ((values.password?.length ?? 0) < 12) return "Password must be at least 12 characters.";
  if (mode === "signup" && values.password !== values.confirmPassword) return "Passwords do not match.";
  return null;
}

interface ApiProject {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly settings?: { readonly defaultEnvironments?: readonly string[] };
  readonly environments?: readonly { readonly slug: string }[];
  readonly tags?: readonly { readonly name: string }[];
}

function toProjectLink(project: ApiProject): ProjectQuickLink {
  return {
    id: project.id,
    name: project.name,
    slug: project.slug,
    environments: project.environments?.map(({ slug }) => slug) ?? project.settings?.defaultEnvironments ?? [],
    tags: (project.tags ?? []).map(({ name }) => name),
  };
}

export async function createProject(
  input: { readonly name: string; readonly slug: string },
  request: RequestFunction = apiFetch,
): Promise<ProjectQuickLink> {
  const response = await request("/api/v1/projects", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  const payload = await response.json().catch(() => null) as { data?: ApiProject; error?: { message?: string } } | null;
  if (!response.ok) throw new Error(payload?.error?.message ?? "Project could not be created.");
  if (payload?.data?.id === undefined || payload.data.name === undefined || payload.data.slug === undefined) {
    throw new Error("Project response was incomplete.");
  }
  return toProjectLink(payload.data);
}

export async function fetchProjects(request: RequestFunction = apiFetch): Promise<readonly ProjectQuickLink[]> {
  const response = await request("/api/v1/projects?limit=100");
  const payload = await response.json().catch(() => null) as { data?: readonly ApiProject[]; error?: { message?: string } } | null;
  if (!response.ok || payload?.data === undefined) throw new Error(payload?.error?.message ?? "Projects could not be loaded.");
  return payload.data.map(toProjectLink);
}

async function fetchEnvironments(projectId: string, request: RequestFunction = apiFetch): Promise<readonly EnvironmentView[]> {
  const response = await request(`/api/v1/projects/${encodeURIComponent(projectId)}/environments`);
  const payload = await response.json().catch(() => null) as {
    data?: readonly { id: string; name: string; slug: string; protected: boolean }[];
    error?: { message?: string };
  } | null;
  if (!response.ok || payload?.data === undefined) throw new Error(payload?.error?.message ?? "Environments could not be loaded.");
  return payload.data.map(({ id, name, slug, protected: isProtected }) => ({ id, name, slug, protected: isProtected }));
}

export interface AppRoutesProps {
  /** Session injection for tests; the browser bootstraps from GET /api/v1/session. */
  readonly initialSession?: SessionView | null;
  readonly initialProjects?: readonly ProjectQuickLink[];
}

export function AppRoutes({ initialSession, initialProjects }: AppRoutesProps = {}): ReactNode {
  const [session, setSession] = useState<SessionView | null | undefined>(initialSession);
  const [sessionError, setSessionError] = useState<string | null>(null);
  useEffect(() => {
    if (session !== undefined) return;
    let cancelled = false;
    fetchSession()
      .then((next) => { if (!cancelled) setSession(next); })
      .catch(() => { if (!cancelled) setSessionError("The workspace could not be reached. Retry in a moment."); });
    return () => { cancelled = true; };
  }, [session]);
  return (
    <Routes>
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/signup" element={<AuthPage mode="signup" />} />
      <Route path="/password-reset" element={<AuthPage mode="password-reset" />} />
      <Route path="/password-reset/confirm" element={<ResetConfirmPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/invites/:token" element={<InvitePage />} />
      <Route
        path="/app"
        element={<AuthenticatedApp session={session} sessionError={sessionError} onSession={setSession} initialProjects={initialProjects} />}
      >
        <Route index element={<Navigate to="projects" replace />} />
        <Route path="projects" element={<ProjectsIndexRoute />} />
        <Route path="projects/:projectId" element={<ProjectLandingRoute />} />
        <Route path="audit" element={<AuditRoute />} />
        <Route path="settings" element={<SettingsRoute />} />
      </Route>
      <Route path="*" element={<Navigate to="/app/projects" replace />} />
    </Routes>
  );
}

interface WorkspaceContext {
  readonly role: SessionOrganization["role"];
  readonly projects: readonly ProjectQuickLink[] | undefined;
  readonly addProject: (project: ProjectQuickLink) => void;
  readonly updateProjectEnvironments: (projectId: string, environments: readonly EnvironmentView[]) => void;
}

function AuthenticatedApp({ session, sessionError, onSession, initialProjects }: {
  session: SessionView | null | undefined;
  sessionError: string | null;
  onSession: (session: SessionView) => void;
  initialProjects?: readonly ProjectQuickLink[] | undefined;
}): ReactNode {
  const activeOrgId = session === null || session === undefined ? null : session.activeOrgId;
  const [projects, setProjects] = useState<readonly ProjectQuickLink[] | undefined>(initialProjects);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  useEffect(() => {
    if (activeOrgId === null) return;
    let cancelled = false;
    setProjectsError(null);
    fetchProjects()
      .then((rows) => { if (!cancelled) setProjects(rows); })
      .catch((reason: unknown) => { if (!cancelled) setProjectsError(reason instanceof Error ? reason.message : "Projects could not be loaded."); });
    return () => { cancelled = true; };
  }, [activeOrgId]);

  if (sessionError !== null) return <SplashScreen message={sessionError} />;
  if (session === undefined) return <SplashScreen message="Opening your workspace…" />;
  if (session === null) return <Navigate to="/login" replace />;
  if (session.activeOrgId === null) return <OrgSetupPage session={session} onSession={onSession} />;
  return (
    <AppShell
      session={session}
      onSession={onSession}
      projects={projects}
      projectsError={projectsError}
      addProject={(project) => setProjects((current) => [...(current ?? []), project])}
      updateProjectEnvironments={(projectId, rows) => setProjects((current) => current?.map((project) => project.id === projectId ? { ...project, environments: rows.map(({ slug }) => slug) } : project))}
    />
  );
}

function SplashScreen({ message }: { message: string }): ReactNode {
  return (
    <div className="auth-layout splash-screen">
      <main className="auth-panel">
        <div className="auth-card">
          <a className="brand" href="/login"><BrandMark /><span>himitsu</span></a>
          <p role="status">{message}</p>
        </div>
      </main>
    </div>
  );
}

function OrgSetupPage({ session, onSession }: { session: SessionView; onSession: (session: SessionView) => void }): ReactNode {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);

  const open = async (orgId: string) => {
    setBusy(true);
    setError(null);
    try { onSession(await switchOrganization(orgId)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The organization could not be opened."); setBusy(false); }
  };
  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try { onSession((await createOrganization(name, slug)).session); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The organization could not be created."); setBusy(false); }
  };

  return (
    <div className="auth-layout">
      <section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">ONE TENANT, ONE BOUNDARY</span><blockquote>Every membership, key, and audit line lives inside the organization you choose here.</blockquote></div></section>
      <main className="auth-panel">
        <div className="auth-card org-setup">
          <span className="kicker">Signed in as {session.user.email}</span>
          <h1>Choose your organization.</h1>
          {session.organizations.length > 0 ? (
            <ul className="org-choice-list" aria-label="Your organizations">
              {session.organizations.map((organization) => (
                <li key={organization.id}>
                  <button type="button" disabled={busy} onClick={() => void open(organization.id)}>
                    <span>{organization.name}</span>
                    <small>{organization.role.replace("_", " ")}</small>
                  </button>
                </li>
              ))}
            </ul>
          ) : <p>You are not a member of an organization yet. Create one to start an encrypted workspace.</p>}
          <form aria-label="Create organization" onSubmit={(event) => void create(event)}>
            <label>Organization name<input value={name} required minLength={1} maxLength={120} placeholder="Northstar Studio" onChange={(event) => { setName(event.target.value); if (!slugEdited) setSlug(suggestSlug(event.target.value)); }} /></label>
            <label>Slug<input value={slug} required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={80} placeholder="northstar-studio" onChange={(event) => { setSlugEdited(true); setSlug(event.target.value); }} /></label>
            {error ? <p className="form-status error" role="alert">{error}</p> : null}
            <button className="auth-submit" type="submit" disabled={busy}>{busy ? "Working…" : "Create organization"}<span>→</span></button>
          </form>
          <div className="auth-links"><button className="link-button" type="button" onClick={() => { void logout().finally(() => window.location.assign("/login")); }}>Sign out</button></div>
        </div>
      </main>
    </div>
  );
}

function AppShell({ session, onSession, projects, projectsError, addProject, updateProjectEnvironments }: {
  session: SessionView;
  onSession: (session: SessionView) => void;
  projects: readonly ProjectQuickLink[] | undefined;
  projectsError: string | null;
  addProject: (project: ProjectQuickLink) => void;
  updateProjectEnvironments: WorkspaceContext["updateProjectEnvironments"];
}): ReactNode {
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    const stored = localStorage.getItem("himitsu-sidebar-collapsed");
    if (stored !== null) return stored === "true";
    return window.matchMedia("(max-width: 980px)").matches;
  });
  const [switchError, setSwitchError] = useState<string | null>(null);
  const organizations = session.organizations;
  const activeOrg = organizations.find(({ id }) => id === session.activeOrgId);
  const commands = useMemo<readonly CommandItem[]>(() => [
    { id: "nav-projects", label: "Projects", eyebrow: "Navigate", to: "/app/projects", search: "projects navigate" },
    { id: "nav-audit", label: "Audit log", eyebrow: "Navigate", to: "/app/audit", search: "audit governance navigate" },
    { id: "nav-settings", label: "Settings", eyebrow: "Navigate", to: "/app/settings", search: "settings members api keys tags navigate" },
    ...(projects ?? []).map((project) => ({
      id: `project-${project.id}`,
      label: project.name,
      eyebrow: "Project",
      to: `/app/projects/${project.id}`,
      search: `${project.name} ${project.slug} project`.toLocaleLowerCase(),
    })),
  ], [projects]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
      if (event.key === "Escape") setPaletteOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    localStorage.setItem("himitsu-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  const switchOrg = async (orgId: string) => {
    setSwitchError(null);
    try {
      onSession(await switchOrganization(orgId));
      navigate("/app/projects");
    } catch (reason) {
      setSwitchError(reason instanceof Error ? reason.message : "The organization could not be switched.");
    }
  };

  const context: WorkspaceContext = { role: activeOrg?.role ?? "read_only", projects, addProject, updateProjectEnvironments };

  return (
    <div className={sidebarCollapsed ? "app-frame sidebar-collapsed" : "app-frame"}>
      <aside className="sidebar">
        <NavLink className="brand" to="/app/projects" aria-label="Himitsu home">
          <BrandMark />
          <span>himitsu</span>
        </NavLink>
        <button
          className="sidebar-toggle"
          type="button"
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!sidebarCollapsed}
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
        >
          <Icon name={sidebarCollapsed ? "chevron-right" : "chevron-left"} />
        </button>
        <nav className="primary-nav" aria-label="Primary navigation">
          <NavigationLink to="/app/projects" label="Projects" icon="grid" />
          <NavigationLink to="/app/audit" label="Audit" icon="pulse" />
          <NavigationLink to="/app/settings" label="Settings" icon="sliders" />
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" />
          {/* The build label nests inside the last span so the existing
              .sidebar-collapsed rule hides it along with the status text. */}
          <span>Systems normal<small className="build-tag" title="Deployed build">{BUILD_LABEL}</small></span>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <label className="org-switcher">
            <span className="sr-only">Active organization</span>
            <span className="org-monogram" aria-hidden="true">{activeOrg?.name.slice(0, 1) ?? "H"}</span>
            <Select value={session.activeOrgId ?? ""} onValueChange={(value) => void switchOrg(value)} aria-label="Active organization" options={organizations.map((organization) => ({ value: organization.id, label: organization.name }))} />
            <span className="role-pill">{(activeOrg?.role ?? "read_only").replace("_", " ")}</span>
          </label>
          <div className="topbar-actions">
            <button className="command-trigger" type="button" onClick={() => setPaletteOpen(true)}>
              <Icon name="search" />
              <span>Jump to anything</span>
              <kbd>⌘ K</kbd>
            </button>
            <ThemeToggle />
            <details className="user-menu">
              <summary aria-label="Open user menu"><span>{initials(session.user.email)}</span></summary>
              <div className="user-popover">
                <strong>{session.user.email}</strong>
                <small>Session expires {new Date(session.expiresAt).toLocaleString()}</small>
                <hr />
                <button className="link-button" type="button" onClick={() => { void logout().finally(() => window.location.assign("/login")); }}>Sign out</button>
              </div>
            </details>
          </div>
        </header>
        <main className="content">
          {switchError ? <p className="form-status error" role="alert">{switchError}</p> : null}
          {projectsError ? <p className="form-status error" role="alert">{projectsError}</p> : null}
          <Outlet context={context} />
        </main>
      </div>
      {paletteOpen ? (
        <CommandPalette
          items={commands}
          onClose={() => setPaletteOpen(false)}
          onSelect={(to) => { setPaletteOpen(false); navigate(to); }}
        />
      ) : null}
    </div>
  );
}

function ProjectsIndexRoute(): ReactNode {
  const { projects, addProject } = useOutletContext<WorkspaceContext>();
  return <ProjectsPage projects={projects} onCreated={addProject} />;
}

function ProjectLandingRoute(): ReactNode {
  const { role, projects, updateProjectEnvironments } = useOutletContext<WorkspaceContext>();
  return <ProjectLanding role={role} projects={projects} onEnvironmentsChange={updateProjectEnvironments} />;
}

function AuditRoute(): ReactNode {
  const { role } = useOutletContext<WorkspaceContext>();
  return <AuditPage role={role} />;
}

function SettingsRoute(): ReactNode {
  const { role, projects } = useOutletContext<WorkspaceContext>();
  return <SettingsPage role={role} projects={(projects ?? []).map(({ id, name }) => ({ id, name }))} />;
}

function NavigationLink({ to, label, icon }: { to: string; label: string; icon: IconName }): ReactNode {
  return <NavLink to={to} aria-label={label} title={label} className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}><Icon name={icon} /><span>{label}</span></NavLink>;
}

function CommandPalette({ items, onClose, onSelect }: {
  items: readonly CommandItem[];
  onClose: () => void;
  onSelect: (to: string) => void;
}): ReactNode {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const results = filterCommandItems(items, query).slice(0, 8);
  useEffect(() => inputRef.current?.focus(), []);
  return (
    <div className="palette-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="command-palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="palette-search"><Icon name="search" /><input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects and pages…" /><kbd>esc</kbd></div>
        <div className="palette-results">
          {results.length > 0 ? results.map((item) => (
            <button key={item.id} type="button" onClick={() => onSelect(item.to)}>
              <span><small>{item.eyebrow}</small>{item.label}</span><span aria-hidden="true">↗</span>
            </button>
          )) : <p className="empty-result">No matches. Try a project name or page.</p>}
        </div>
        <footer><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span></footer>
      </section>
    </div>
  );
}

function ProjectsPage({ projects, onCreated }: { projects: readonly ProjectQuickLink[] | undefined; onCreated: (project: ProjectQuickLink) => void }): ReactNode {
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [projectName, setProjectName] = useState("");
  const [projectSlug, setProjectSlug] = useState("");
  const [projectSlugEdited, setProjectSlugEdited] = useState(false);
  const [query, setQuery] = useState("");
  const [activeTag, setActiveTag] = useState<string | null>(null);
  const loaded = projects ?? [];
  const tags = [...new Set(loaded.flatMap((project) => project.tags))].sort();
  const environmentCount = new Set(loaded.flatMap((project) => project.environments)).size;
  const visibleProjects = useMemo(() => filterProjectLinks(loaded, query, activeTag), [loaded, query, activeTag]);
  const openCreator = () => {
    setProjectName("");
    setProjectSlug("");
    setProjectSlugEdited(false);
    setError(null);
    setCreating(true);
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const project = await createProject({ name: projectName, slug: projectSlug });
      onCreated(project);
      navigate(`/app/projects/${project.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Project could not be created.");
      setBusy(false);
    }
  };
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Workspace" title="Projects" copy="Encrypted configuration, arranged around the way your systems move." action="New project" onAction={openCreator} />
      {creating ? <form className="editor-sheet project-creator" aria-label="Create project" onSubmit={(event) => void submit(event)}>
        <header><div><span className="kicker">New encrypted workspace</span><h2>Create a project</h2></div><button type="button" aria-label="Close project form" onClick={() => setCreating(false)}>×</button></header>
        <label>Name<input name="name" value={projectName} required minLength={1} maxLength={120} autoFocus placeholder="Payments API" onChange={(event) => { setProjectName(event.target.value); if (!projectSlugEdited) setProjectSlug(suggestSlug(event.target.value)); }} /></label>
        <label>Slug<input name="slug" value={projectSlug} required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={80} placeholder="payments-api" onChange={(event) => { setProjectSlugEdited(true); setProjectSlug(event.target.value); }} /></label>
        {error ? <p className="form-status error" role="alert">{error}</p> : null}
        <footer><button className="secondary-button" type="button" onClick={() => setCreating(false)}>Cancel</button><button className="primary-button" type="submit" disabled={busy}>{busy ? "Creating…" : "Create project"}</button></footer>
      </form> : null}
      <section className="signal-strip" aria-label="Workspace health">
        <Metric value={loaded.length.toString().padStart(2, "0")} label="active projects" />
        <Metric value={environmentCount.toString().padStart(2, "0")} label="environments" />
        <Metric value="100%" label="encrypted" accent />
        <Metric value="0" label="open alerts" />
      </section>
      {projects === undefined ? <section className="quiet-panel" aria-busy="true"><BrandMark /><h2>Loading projects…</h2><p>Fetching the encrypted workspaces in this organization.</p></section>
        : loaded.length === 0 ? <FirstRunChecklist onCreate={openCreator} /> : <><section className="secret-toolbar project-filters" aria-label="Filter projects"><label className="secret-search"><span aria-hidden="true">⌕</span><span className="sr-only">Search projects</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects or tags" /></label><div className="tag-filters"><button type="button" className={activeTag === null ? "active" : ""} onClick={() => setActiveTag(null)}>All</button>{tags.map((tag) => <button type="button" key={tag} className={activeTag === tag ? "active" : ""} onClick={() => setActiveTag(tag)}>#{tag}</button>)}</div><span className="row-count">{visibleProjects.length} / {loaded.length}</span></section>
      <section className="project-grid" aria-label="Projects">
        {visibleProjects.map((project, index) => (
          <NavLink className="project-card" to={`/app/projects/${project.id}`} key={project.id}>
            <span className="card-index">{(index + 1).toString().padStart(2, "0")}</span>
            <div><small>PROJECT</small><h2>{project.name}</h2><p>{project.slug}</p></div>
            <div className="environment-row">{project.environments.slice(0, 3).map((environment) => <span key={environment}>{environment.slice(0, 3).toUpperCase()}</span>)}</div>
            <div className="row-tags">{project.tags.map((tag) => <span key={tag}>#{tag}</span>)}</div>
            <footer><span>{project.environments.length} environments</span><span>View project →</span></footer>
          </NavLink>
        ))}
      </section></>}
    </div>
  );
}

function FirstRunChecklist({ onCreate }: { onCreate: () => void }): ReactNode {
  return <section className="onboarding-panel" aria-labelledby="onboarding-heading"><header><span className="kicker">First-run checklist</span><h2 id="onboarding-heading">Build your first encrypted workflow.</h2><p>Four small steps take a new organization from an empty workspace to CI-ready secret delivery.</p></header><ol><li className="complete"><i>✓</i><span><strong>Organization ready</strong><small>Your tenant boundary and audit trail are active.</small></span></li><li className="current"><i>2</i><span><strong>Create a project</strong><small>Projects group environments and their encrypted configuration.</small></span><button className="primary-button" type="button" onClick={onCreate}>Create first project</button></li><li><i>3</i><span><strong>Import your .env</strong><small>Open the project and use Bulk paste to preview before writing.</small></span></li><li><i>4</i><span><strong>Connect CI or runtime</strong><small>Create a scoped read-only API key in Settings, then use the CLI or runtime endpoint.</small></span></li></ol><footer><span>The repository guide mirrors this checklist with copy-ready CLI and CI commands.</span><NavLink to="/app/settings">Prepare CI access →</NavLink></footer></section>;
}

function ProjectLanding({ role, projects, onEnvironmentsChange }: { role: SessionOrganization["role"]; projects: readonly ProjectQuickLink[] | undefined; onEnvironmentsChange: (projectId: string, environments: readonly EnvironmentView[]) => void }): ReactNode {
  const { projectId } = useParams();
  const [environments, setEnvironments] = useState<readonly EnvironmentView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const project = projects?.find(({ id }) => id === projectId);
  useEffect(() => {
    if (projectId === undefined) return;
    let cancelled = false;
    setEnvironments(null);
    setError(null);
    fetchEnvironments(projectId)
      .then((rows) => { if (!cancelled) setEnvironments(rows); })
      .catch((reason: unknown) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "Environments could not be loaded."); });
    return () => { cancelled = true; };
  }, [projectId]);
  if (projects === undefined) return <SectionPage eyebrow="Project" title="Loading project…" copy="Fetching the project list for this organization." />;
  if (project === undefined) return <SectionPage eyebrow="Project" title="Project not found" copy="This project is not available in the active organization." />;
  if (error !== null) return <SectionPage eyebrow="Project" title={project.name} copy={error} />;
  if (environments === null) return <SectionPage eyebrow="Project" title={project.name} copy="Loading environments…" />;
  return <SecretWorkspace key={project.id} projectId={project.id} projectName={project.name} environments={environments} role={role} onEnvironmentsChange={(rows) => onEnvironmentsChange(project.id, rows)} />;
}

function SectionPage({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }): ReactNode {
  return <div className="page-stack"><PageHeader eyebrow={eyebrow} title={title} copy={copy} /><section className="quiet-panel"><BrandMark /><h2>Foundation ready</h2><p>This workspace is prepared for the next focused workflow.</p></section></div>;
}

function PageHeader({ eyebrow, title, copy, action, onAction }: { eyebrow: string; title: string; copy: string; action?: string; onAction?: () => void }): ReactNode {
  return <header className="page-header"><div><span>{eyebrow}</span><h1>{title}</h1><p>{copy}</p></div>{action ? <button className="primary-button" type="button" onClick={onAction}><span>＋</span>{action}</button> : null}</header>;
}

function Metric({ value, label, accent = false }: { value: string; label: string; accent?: boolean }): ReactNode {
  return <div className={accent ? "metric accent" : "metric"}><strong>{value}</strong><span>{label}</span></div>;
}

function AuthPage({ mode }: { mode: AuthMode }): ReactNode {
  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
  const [searchParams] = useSearchParams();
  const expired = searchParams.get("reason") === "expired";
  const [status, setStatus] = useState<{ kind: "idle" | "busy" | "success" | "error"; message?: string }>(
    expired && mode === "login" ? { kind: "error", message: "Your session ended. Sign in again to continue." } : { kind: "idle" },
  );
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const resend = async () => {
    if (unverifiedEmail === null) return;
    setStatus({ kind: "busy" });
    try {
      await resendVerification(unverifiedEmail);
      setStatus({ kind: "success", message: `A new verification link is on its way to ${unverifiedEmail}. Open it, then sign in.` });
    } catch (reason) {
      setStatus({ kind: "error", message: reason instanceof Error ? reason.message : "The verification email could not be sent." });
    }
  };
  const copy = mode === "login"
    ? { eyebrow: "Welcome back", title: "Enter the vault.", sub: "Your organization’s secrets are waiting—encrypted, traced, and exactly where you left them.", button: "Sign in" }
    : mode === "signup"
      ? { eyebrow: "Create an account", title: "Start with trust.", sub: "Build a private workspace for the configuration your team depends on.", button: "Create account" }
      : { eyebrow: "Account recovery", title: "Reset access.", sub: "We’ll send a single-use recovery link if the address belongs to an account.", button: "Send recovery link" };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const values = {
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
      confirmPassword: String(form.get("confirmPassword") ?? ""),
    };
    const error = validateAuthForm(mode, values);
    if (error !== null) { setStatus({ kind: "error", message: error }); return; }
    setStatus({ kind: "busy" });
    setUnverifiedEmail(null);
    try {
      if (mode === "login") {
        await login(values.email, values.password);
        setStatus({ kind: "success", message: "Signed in. Opening your workspace…" });
        window.location.assign("/app/projects");
      } else if (mode === "signup") {
        await signup(values.email, values.password);
        setUnverifiedEmail(values.email.trim());
        setStatus({ kind: "success", message: "Account created. Open the verification link we sent to your email, then sign in." });
      } else {
        await requestPasswordReset(values.email);
        setStatus({ kind: "success", message: "If that address belongs to an account, a recovery link is on its way." });
      }
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.code === "EMAIL_NOT_VERIFIED") {
        setUnverifiedEmail(values.email.trim());
        setStatus({ kind: "error", message: "This email address has not been verified yet. Open the verification link from your signup email first." });
        return;
      }
      setStatus({ kind: "error", message: requestError instanceof Error ? requestError.message : "The request could not be completed." });
    }
  };

  return (
    <div className="auth-layout">
      <section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">SECRETS, WITHOUT THE SPRAWL</span><blockquote>“The quietest part of your infrastructure should be the part you trust most.”</blockquote></div><footer><span>ENCRYPTED BY DEFAULT</span><span>AUDITED BY DESIGN</span><span title="Deployed build">{BUILD_LABEL}</span></footer></section>
      <main className="auth-panel">
        <ThemeToggle />
        <form className="auth-card" onSubmit={submit} noValidate>
          <span className="kicker">{copy.eyebrow}</span><h1>{copy.title}</h1><p>{copy.sub}</p>
          <label htmlFor={emailId}>Work email<input id={emailId} name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></label>
          {mode !== "password-reset" ? <label htmlFor={passwordId}>Password<input id={passwordId} name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={12} placeholder="At least 12 characters" /></label> : null}
          {mode === "signup" ? <label htmlFor={confirmId}>Confirm password<input id={confirmId} name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} /></label> : null}
          {status.message ? <p className={`form-status ${status.kind}`} role={status.kind === "error" ? "alert" : "status"}>{status.message}</p> : null}
          {unverifiedEmail !== null ? <p className="resend-verification">Didn’t receive an email? <button className="link-button" type="button" disabled={status.kind === "busy"} onClick={() => void resend()}>Send it again</button></p> : null}
          <button className="auth-submit" type="submit" disabled={status.kind === "busy"}>{status.kind === "busy" ? "Working…" : copy.button}<span>→</span></button>
          <AuthLinks mode={mode} />
        </form>
      </main>
    </div>
  );
}

function AuthLinks({ mode }: { mode: AuthMode }): ReactNode {
  if (mode === "login") return <div className="auth-links"><a href="/password-reset">Forgot password?</a><span>New to Himitsu? <a href="/signup">Create an account</a></span></div>;
  if (mode === "signup") return <div className="auth-links"><span>Already have an account? <a href="/login">Sign in</a></span></div>;
  return <div className="auth-links"><a href="/login">← Back to sign in</a></div>;
}

function VerifyEmailPage(): ReactNode {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [status, setStatus] = useState(token === "" ? "This verification link is incomplete. Open the full link from your email." : "Verifying your email address…");
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (token === "") return;
    let cancelled = false;
    verifyEmail(token)
      .then(() => { if (!cancelled) { setStatus("Email verified. You can sign in now."); setDone(true); } })
      .catch((reason: unknown) => { if (!cancelled) setStatus(reason instanceof Error ? reason.message : "The verification link is invalid or expired."); });
    return () => { cancelled = true; };
  }, [token]);
  return (
    <div className="auth-layout">
      <section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">VERIFIED, THEN TRUSTED</span><blockquote>Ownership of the address is the first credential.</blockquote></div></section>
      <main className="auth-panel">
        <div className="auth-card">
          <span className="kicker">Email verification</span>
          <h1>{done ? "You’re verified." : "One moment."}</h1>
          <p role="status">{status}</p>
          <div className="auth-links"><a href="/login">{done ? "Continue to sign in →" : "← Back to sign in"}</a></div>
        </div>
      </main>
    </div>
  );
}

function ResetConfirmPage(): ReactNode {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const passwordId = useId();
  const confirmId = useId();
  const [status, setStatus] = useState<{ kind: "idle" | "busy" | "success" | "error"; message?: string }>(
    token === "" ? { kind: "error", message: "This recovery link is incomplete. Open the full link from your email." } : { kind: "idle" },
  );
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    if (password.length < 12) { setStatus({ kind: "error", message: "Password must be at least 12 characters." }); return; }
    if (password !== String(form.get("confirmPassword") ?? "")) { setStatus({ kind: "error", message: "Passwords do not match." }); return; }
    setStatus({ kind: "busy" });
    try {
      await confirmPasswordReset(token, password);
      setStatus({ kind: "success", message: "Password updated. Sign in with your new password." });
    } catch (reason) {
      setStatus({ kind: "error", message: reason instanceof Error ? reason.message : "The recovery link is invalid or expired." });
    }
  };
  return (
    <div className="auth-layout">
      <section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">ACCOUNT RECOVERY</span><blockquote>A single-use link, a fresh credential, and every old session revoked.</blockquote></div></section>
      <main className="auth-panel">
        <form className="auth-card" onSubmit={(event) => void submit(event)} noValidate>
          <span className="kicker">Set a new password</span>
          <h1>Choose carefully.</h1>
          <p>Resetting your password signs out every existing session for this account.</p>
          <label htmlFor={passwordId}>New password<input id={passwordId} name="password" type="password" autoComplete="new-password" required minLength={12} placeholder="At least 12 characters" /></label>
          <label htmlFor={confirmId}>Confirm password<input id={confirmId} name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} /></label>
          {status.message ? <p className={`form-status ${status.kind}`} role={status.kind === "error" ? "alert" : "status"}>{status.message}</p> : null}
          <button className="auth-submit" type="submit" disabled={status.kind === "busy" || token === "" || status.kind === "success"}>{status.kind === "busy" ? "Working…" : "Update password"}<span>→</span></button>
          <div className="auth-links"><a href="/login">← Back to sign in</a></div>
        </form>
      </main>
    </div>
  );
}

function InvitePage(): ReactNode {
  const { token = "" } = useParams();
  const [status, setStatus] = useState("Your invitation is ready to accept.");
  const [needsLogin, setNeedsLogin] = useState(false);
  const accept = async () => {
    try {
      await acceptInvitation(token);
      setStatus("Invitation accepted. Opening your workspace…");
      window.location.assign("/app/projects");
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        setNeedsLogin(true);
        setStatus("Sign in (or create an account) first, then reopen this invitation link.");
        return;
      }
      setStatus(error instanceof Error ? error.message : "Invitation could not be accepted.");
    }
  };
  return <div className="auth-layout invite-layout"><section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">PRIVATE BY INVITATION</span><blockquote>Join the workspace without moving trust outside its boundary.</blockquote></div></section><main className="auth-panel"><div className="auth-card"><span className="kicker">Organization invite</span><h1>You’re invited.</h1><p role="status">{status}</p><button className="auth-submit" type="button" onClick={() => void accept()}>Accept invitation <span>→</span></button><div className="auth-links">{needsLogin ? <a href="/login">Sign in →</a> : <a href="/login">Use a different account</a>}</div></div></main></div>;
}

function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    if (typeof document === "undefined") return "dark";
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("himitsu-theme", theme);
  }, [theme]);
  return <button className="icon-button" type="button" onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")} aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}><Icon name={theme === "dark" ? "sun" : "moon"} /></button>;
}

function BrandMark(): ReactNode {
  return <svg className="brand-mark" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path fillRule="evenodd" d="M12 2.3 19.4 5.35v6.1c0 4.6-3 8.5-7.4 10.25C7.6 19.95 4.6 16.05 4.6 11.45v-6.1ZM12 8.25a2.15 2.15 0 0 0-1.05 4.03L10.3 15.5h3.4l-.65-3.22A2.15 2.15 0 0 0 12 8.25Z" />
  </svg>;
}
function initials(email: string): string {
  const local = email.split("@")[0] ?? "";
  return local.split(/[._-]+/).map((part) => part[0]).filter(Boolean).slice(0, 2).join("").toUpperCase() || "U";
}

type IconName = "grid" | "pulse" | "sliders" | "search" | "sun" | "moon" | "chevron-left" | "chevron-right";
function Icon({ name }: { name: IconName }): ReactNode {
  const paths: Record<IconName, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    pulse: <><path d="M3 12h4l2-6 4 12 2-6h6"/><path d="M4 4v16h16"/></>,
    sliders: <><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="11" cy="18" r="2"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
    moon: <path d="M20 15.5A8 8 0 0 1 8.5 4 8.5 8.5 0 1 0 20 15.5Z"/>,
    "chevron-left": <path d="m14 7-5 5 5 5"/>,
    "chevron-right": <path d="m10 7 5 5-5 5"/>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
