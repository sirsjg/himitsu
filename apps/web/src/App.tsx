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
  useParams,
} from "react-router-dom";

export interface OrganizationOption {
  readonly id: string;
  readonly name: string;
  readonly role: "owner" | "admin" | "member" | "read_only";
}

export interface ProjectQuickLink {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly secrets: readonly string[];
}

export interface CurrentUser {
  readonly name: string;
  readonly email: string;
}

export interface CommandItem {
  readonly id: string;
  readonly label: string;
  readonly eyebrow: string;
  readonly to: string;
  readonly search: string;
}

export type AuthMode = "login" | "signup" | "password-reset";

export const demoOrganizations: readonly OrganizationOption[] = [
  { id: "org-studio", name: "Northstar Studio", role: "owner" },
  { id: "org-labs", name: "Field Labs", role: "member" },
];

export const demoProjects: readonly ProjectQuickLink[] = [
  { id: "project-atlas", name: "Atlas API", slug: "atlas-api", secrets: ["DATABASE_URL", "STRIPE_SECRET_KEY"] },
  { id: "project-lantern", name: "Lantern Web", slug: "lantern-web", secrets: ["AUTH_ORIGIN", "SENTRY_DSN"] },
  { id: "project-relay", name: "Relay Worker", slug: "relay-worker", secrets: ["QUEUE_URL", "WORKER_TOKEN"] },
];

export function filterCommandItems(items: readonly CommandItem[], query: string): readonly CommandItem[] {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return items;
  return items.filter(({ search }) => terms.every((term) => search.includes(term)));
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

async function postJson(path: string, body: Readonly<Record<string, string>>): Promise<void> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: { message?: string } } | null;
    throw new Error(payload?.error?.message ?? "The request could not be completed.");
  }
}

export interface AppRoutesProps {
  readonly organizations?: readonly OrganizationOption[];
  readonly projects?: readonly ProjectQuickLink[];
  readonly user?: CurrentUser;
}

export function AppRoutes({
  organizations = demoOrganizations,
  projects = demoProjects,
  user = { name: "Akari Mori", email: "akari@example.com" },
}: AppRoutesProps): ReactNode {
  return (
    <Routes>
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/signup" element={<AuthPage mode="signup" />} />
      <Route path="/password-reset" element={<AuthPage mode="password-reset" />} />
      <Route path="/invites/:token" element={<InvitePage />} />
      <Route path="/app" element={<AppShell organizations={organizations} projects={projects} user={user} />}>
        <Route index element={<Navigate to="projects" replace />} />
        <Route path="projects" element={<ProjectsPage projects={projects} />} />
        <Route path="projects/:projectId" element={<ProjectLanding projects={projects} />} />
        <Route path="audit" element={<SectionPage eyebrow="Governance" title="Audit log" copy="Trace sensitive activity across your organization with immutable, secret-safe records." />} />
        <Route path="settings" element={<SectionPage eyebrow="Workspace" title="Settings" copy="Manage members, access, service credentials, tags, and organization policy." />} />
      </Route>
      <Route path="*" element={<Navigate to="/app/projects" replace />} />
    </Routes>
  );
}

function AppShell({
  organizations,
  projects,
  user,
}: Required<Pick<AppRoutesProps, "organizations" | "projects" | "user">>): ReactNode {
  const navigate = useNavigate();
  const [organizationId, setOrganizationId] = useState(organizations[0]?.id ?? "");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const activeOrg = organizations.find(({ id }) => id === organizationId) ?? organizations[0];
  const commands = useMemo<readonly CommandItem[]>(() => [
    { id: "nav-projects", label: "Projects", eyebrow: "Navigate", to: "/app/projects", search: "projects navigate" },
    { id: "nav-audit", label: "Audit log", eyebrow: "Navigate", to: "/app/audit", search: "audit governance navigate" },
    { id: "nav-settings", label: "Settings", eyebrow: "Navigate", to: "/app/settings", search: "settings members api keys tags navigate" },
    ...projects.flatMap((project) => [
      { id: `project-${project.id}`, label: project.name, eyebrow: "Project", to: `/app/projects/${project.id}`, search: `${project.name} ${project.slug} project`.toLocaleLowerCase() },
      ...project.secrets.map((secret) => ({
        id: `secret-${project.id}-${secret}`,
        label: secret,
        eyebrow: project.name,
        to: `/app/projects/${project.id}?secret=${encodeURIComponent(secret)}`,
        search: `${secret} ${project.name} ${project.slug} secret`.toLocaleLowerCase(),
      })),
    ]),
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

  return (
    <div className="app-frame">
      <aside className="sidebar">
        <NavLink className="brand" to="/app/projects" aria-label="Himitsu home">
          <BrandMark />
          <span>himitsu</span>
        </NavLink>
        <nav className="primary-nav" aria-label="Primary navigation">
          <NavigationLink to="/app/projects" label="Projects" icon="grid" />
          <NavigationLink to="/app/audit" label="Audit" icon="pulse" />
          <NavigationLink to="/app/settings" label="Settings" icon="sliders" />
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" />
          <span>Systems normal</span>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <label className="org-switcher">
            <span className="sr-only">Active organization</span>
            <span className="org-monogram" aria-hidden="true">{activeOrg?.name.slice(0, 1) ?? "H"}</span>
            <select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>
              {organizations.map((organization) => (
                <option key={organization.id} value={organization.id}>{organization.name}</option>
              ))}
            </select>
            <span className="role-pill">{activeOrg?.role.replace("_", " ")}</span>
          </label>
          <div className="topbar-actions">
            <button className="command-trigger" type="button" onClick={() => setPaletteOpen(true)}>
              <Icon name="search" />
              <span>Jump to anything</span>
              <kbd>⌘ K</kbd>
            </button>
            <ThemeToggle />
            <details className="user-menu">
              <summary aria-label="Open user menu"><span>{initials(user.name)}</span></summary>
              <div className="user-popover">
                <strong>{user.name}</strong>
                <small>{user.email}</small>
                <hr />
                <a href="/login">Sign out</a>
              </div>
            </details>
          </div>
        </header>
        <main className="content"><Outlet /></main>
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

function NavigationLink({ to, label, icon }: { to: string; label: string; icon: IconName }): ReactNode {
  return <NavLink to={to} className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}><Icon name={icon} /><span>{label}</span></NavLink>;
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
        <div className="palette-search"><Icon name="search" /><input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects, secrets, and pages…" /><kbd>esc</kbd></div>
        <div className="palette-results">
          {results.length > 0 ? results.map((item) => (
            <button key={item.id} type="button" onClick={() => onSelect(item.to)}>
              <span><small>{item.eyebrow}</small>{item.label}</span><span aria-hidden="true">↗</span>
            </button>
          )) : <p className="empty-result">No matches. Try a project name or secret key.</p>}
        </div>
        <footer><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span></footer>
      </section>
    </div>
  );
}

function ProjectsPage({ projects }: { projects: readonly ProjectQuickLink[] }): ReactNode {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Workspace" title="Projects" copy="Encrypted configuration, arranged around the way your systems move." action="New project" />
      <section className="signal-strip" aria-label="Workspace health">
        <Metric value={projects.length.toString().padStart(2, "0")} label="active projects" />
        <Metric value="03" label="environments" />
        <Metric value="100%" label="encrypted" accent />
        <Metric value="0" label="open alerts" />
      </section>
      <section className="project-grid" aria-label="Projects">
        {projects.map((project, index) => (
          <NavLink className="project-card" to={`/app/projects/${project.id}`} key={project.id}>
            <span className="card-index">0{index + 1}</span>
            <div><small>PROJECT</small><h2>{project.name}</h2><p>{project.slug}</p></div>
            <div className="environment-row"><span>DEV</span><span>STG</span><span>PRD</span></div>
            <footer><span>{project.secrets.length} indexed keys</span><span>View project →</span></footer>
          </NavLink>
        ))}
      </section>
    </div>
  );
}

function ProjectLanding({ projects }: { projects: readonly ProjectQuickLink[] }): ReactNode {
  const { projectId } = useParams();
  const project = projects.find(({ id }) => id === projectId);
  if (project === undefined) return <SectionPage eyebrow="Project" title="Project not found" copy="This project is not available in the active organization." />;
  return <SectionPage eyebrow="Project overview" title={project.name} copy={`${project.secrets.length} indexed keys across development, staging, and production.`} />;
}

function SectionPage({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }): ReactNode {
  return <div className="page-stack"><PageHeader eyebrow={eyebrow} title={title} copy={copy} /><section className="quiet-panel"><BrandMark /><h2>Foundation ready</h2><p>This workspace is prepared for the next focused workflow.</p></section></div>;
}

function PageHeader({ eyebrow, title, copy, action }: { eyebrow: string; title: string; copy: string; action?: string }): ReactNode {
  return <header className="page-header"><div><span>{eyebrow}</span><h1>{title}</h1><p>{copy}</p></div>{action ? <button className="primary-button" type="button"><span>＋</span>{action}</button> : null}</header>;
}

function Metric({ value, label, accent = false }: { value: string; label: string; accent?: boolean }): ReactNode {
  return <div className={accent ? "metric accent" : "metric"}><strong>{value}</strong><span>{label}</span></div>;
}

function AuthPage({ mode }: { mode: AuthMode }): ReactNode {
  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
  const [status, setStatus] = useState<{ kind: "idle" | "busy" | "success" | "error"; message?: string }>({ kind: "idle" });
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
    try {
      await postJson(`/api/v1/auth/${mode}`, values);
      setStatus({ kind: "success", message: mode === "login" ? "Signed in. Opening your workspace…" : "Check your inbox for the next step." });
      if (mode === "login" && typeof window !== "undefined") window.setTimeout(() => window.location.assign("/app/projects"), 350);
    } catch (requestError) {
      setStatus({ kind: "error", message: requestError instanceof Error ? requestError.message : "The request could not be completed." });
    }
  };

  return (
    <div className="auth-layout">
      <section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">SECRETS, WITHOUT THE SPRAWL</span><blockquote>“The quietest part of your infrastructure should be the part you trust most.”</blockquote></div><footer><span>ENCRYPTED BY DEFAULT</span><span>AUDITED BY DESIGN</span></footer></section>
      <main className="auth-panel">
        <ThemeToggle />
        <form className="auth-card" onSubmit={submit} noValidate>
          <span className="kicker">{copy.eyebrow}</span><h1>{copy.title}</h1><p>{copy.sub}</p>
          <label htmlFor={emailId}>Work email<input id={emailId} name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></label>
          {mode !== "password-reset" ? <label htmlFor={passwordId}>Password<input id={passwordId} name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={12} placeholder="At least 12 characters" /></label> : null}
          {mode === "signup" ? <label htmlFor={confirmId}>Confirm password<input id={confirmId} name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} /></label> : null}
          {status.message ? <p className={`form-status ${status.kind}`} role="status">{status.message}</p> : null}
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

function InvitePage(): ReactNode {
  const { token = "" } = useParams();
  const [status, setStatus] = useState("Your invitation is ready to accept.");
  const accept = async () => {
    try { await postJson(`/api/v1/invitations/${encodeURIComponent(token)}/accept`, {}); setStatus("Invitation accepted. Opening your workspace…"); }
    catch (error) { setStatus(error instanceof Error ? error.message : "Invitation could not be accepted."); }
  };
  return <div className="auth-layout invite-layout"><section className="auth-story"><a className="brand" href="/login"><BrandMark /><span>himitsu</span></a><div><span className="kicker">PRIVATE BY INVITATION</span><blockquote>Join the workspace without moving trust outside its boundary.</blockquote></div></section><main className="auth-panel"><div className="auth-card"><span className="kicker">Organization invite</span><h1>You’re invited.</h1><p role="status">{status}</p><button className="auth-submit" type="button" onClick={() => void accept()}>Accept invitation <span>→</span></button><div className="auth-links"><a href="/login">Use a different account</a></div></div></main></div>;
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

function BrandMark(): ReactNode { return <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>; }
function initials(name: string): string { return name.split(/\s+/).map((part) => part[0]).filter(Boolean).slice(0, 2).join("").toUpperCase(); }

type IconName = "grid" | "pulse" | "sliders" | "search" | "sun" | "moon";
function Icon({ name }: { name: IconName }): ReactNode {
  const paths: Record<IconName, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    pulse: <><path d="M3 12h4l2-6 4 12 2-6h6"/><path d="M4 4v16h16"/></>,
    sliders: <><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="11" cy="18" r="2"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
    moon: <path d="M20 15.5A8 8 0 0 1 8.5 4 8.5 8.5 0 1 0 20 15.5Z"/>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
