import { api } from "./api.js";
import { buildConsole } from "./console.js";
import { el, emptyState, fmtDate, openModal, promptText, setHeader, table, toast, view } from "./dom.js";
import { buildProjectCredentials } from "./project_credentials.js";
import { openDeleteSecret, openExportDialog, openImportDialog, openRevealDialog, openSecretDialog } from "./secrets.js";
import { state } from "./state.js";

export async function loadProjects() {
  const data = await api("/v1/projects");
  state.projects = data.items;
  return state.projects;
}

export async function renderProjects() {
  setHeader("Projects", "Each project has its own directory and independent environments.", [
    { label: "Refresh", onClick: renderProjects },
    { label: "New project", primary: true, onClick: () => openProjectDialog() },
  ]);
  const projects = await loadProjects();
  if (!projects.length) {
    view().replaceChildren(
      emptyState(
        "No projects yet",
        "Register a repository directory to import or create secrets.",
        "Register first project",
        () => openProjectDialog(),
      ),
    );
    return;
  }
  const rows = projects.map((project) => [
    el("span", { class: "tag" }, project.slug),
    project.name,
    el("span", { class: "mono muted" }, project.path),
    String(project.secret_count),
    project.environments.length
      ? el("div", { class: "row" }, ...project.environments.map((env) => el("span", { class: "tag" }, `${env.environment} · ${env.count}`)))
      : el("span", { class: "muted" }, "—"),
    el(
      "button",
      {
        class: "btn small",
        type: "button",
        onclick: (event) => {
          event.stopPropagation();
          location.hash = `#/projects/${project.id}`;
        },
      },
      "Open",
    ),
  ]);
  view().replaceChildren(
    table(["slug", "name", "directory", "secrets", "environments", ""], rows, {
      onRowClick: (tr) => {
        const index = Array.from(tr.parentNode.children).indexOf(tr);
        location.hash = `#/projects/${projects[index].id}`;
      },
    }),
  );
}

export async function loadProjectCredentials(projectId) {
  const [scoped, globals] = await Promise.all([
    api(`/v1/credentials?project_id=${encodeURIComponent(projectId)}`),
    api("/v1/credentials?global_only=true"),
  ]);
  return [...scoped.items, ...globals.items];
}

export async function refreshProject() {
  if (!state.project) return;
  state.project = await api(`/v1/projects/${state.project.id}`);
  const environments = state.project.environments.map((item) => item.environment);
  if (!state.environment) {
    state.environment = environments[0] || "dev";
  }
  const [data, credentials] = await Promise.all([
    api(
      `/v1/projects/${state.project.id}/secrets?environment=${encodeURIComponent(state.environment)}`,
    ),
    loadProjectCredentials(state.project.id),
  ]);
  state.secrets = data.items;
  state.projectCredentials = credentials;
  renderProjectPage();
}

export async function renderProject(id) {
  const project = await api(`/v1/projects/${id}`);
  if (!state.project || state.project.id !== project.id) {
    state.environment = null;
  }
  state.project = project;
  const environments = project.environments.map((item) => item.environment);
  if (!state.environment || !environments.includes(state.environment)) {
    state.environment = environments[0] || "dev";
  }
  const [data, credentials] = await Promise.all([
    api(
      `/v1/projects/${project.id}/secrets?environment=${encodeURIComponent(state.environment)}`,
    ),
    loadProjectCredentials(project.id),
  ]);
  state.secrets = data.items;
  state.projectCredentials = credentials;
  renderProjectPage();
}

export function renderProjectPage() {
  const project = state.project;
  const envs = project.environments.map((item) => item.environment);
  if (!envs.includes(state.environment)) envs.unshift(state.environment);
  const env = state.environment;
  setHeader(project.name, `${project.slug} · ${project.path}`, [
    { label: "Credentials", onClick: () => {
        state.credentialFilter = { query: "", category: "", project: project.id };
        location.hash = "#/credentials";
      } },
    { label: "Edit", onClick: () => openProjectDialog(project) },
    { label: "Delete", danger: true, onClick: () => openDeleteProject(project) },
    { label: "Refresh", onClick: refreshProject },
  ]);

  const tabs = el(
    "div",
    { class: "env-tabs" },
    ...envs.map((name) => {
      const button = el("button", { class: `env-tab ${name === env ? "active" : ""}`, type: "button" }, name);
      button.addEventListener("click", () => {
        state.environment = name;
        refreshProject();
      });
      return button;
    }),
    el(
      "button",
      {
        class: "env-tab",
        type: "button",
        onclick: async () => {
          const name = await promptText("New environment", "Short name, e.g. staging", "staging");
          if (!name) return;
          const normalized = name.trim().toLowerCase();
          try {
            await api(`/v1/projects/${project.id}/environments`, {
              method: "POST",
              body: { name: normalized },
            });
            state.environment = normalized;
            await refreshProject();
            toast(`Environment ${normalized} ready.`);
          } catch (error) {
            toast(error.message, "error");
          }
        },
      },
      "+ environment",
    ),
  );

  const actions = el(
    "div",
    { class: "row" },
    el("button", { class: "btn primary", type: "button", onclick: () => openSecretDialog(project, env) }, "New secret"),
    el("button", { class: "btn", type: "button", onclick: () => openImportDialog(project, env) }, "Import .env"),
    el("button", { class: "btn", type: "button", onclick: () => openExportDialog(project, env) }, "Export .env"),
  );

  const rows = state.secrets.map((secret) => [
    el("span", { class: "mono" }, secret.key),
    el("span", { class: "tag" }, `v${secret.version}`),
    fmtDate(secret.updated_at),
    el(
      "div",
      { class: "row" },
      el("button", { class: "btn small", type: "button", onclick: () => openRevealDialog(project, env, secret) }, "Reveal"),
      el("button", { class: "btn small", type: "button", onclick: () => openSecretDialog(project, env, secret) }, "Edit"),
      el("button", { class: "btn small danger", type: "button", onclick: () => openDeleteSecret(project, env, secret) }, "Delete"),
    ),
  ]);

  const secretsSection = state.secrets.length
    ? table(["key", "version", "updated", ""], rows)
    : emptyState(
        `No secrets in ${env}`,
        "Add one manually, generate a password, or import a .env file.",
        "Add secret",
        () => openSecretDialog(project, env),
      );

  const consoleCard = buildConsole(project, env);
  const credentialsSection = buildProjectCredentials(project);
  const info = el(
    "div",
    { class: "card stack" },
    el(
      "div",
      { class: "row" },
      el("span", { class: "tag" }, project.slug),
      ...project.environments.map((item) => el("span", { class: "tag" }, `${item.environment}: ${item.count}`)),
    ),
    el("p", { class: "muted" }, `Directory: ${project.path}`),
    el(
      "p",
      { class: "muted" },
      "Injection happens inside the daemon. The child process receives the variables; output is redacted before it returns to the screen or to the agent.",
    ),
  );

  view().replaceChildren(
    el(
      "div",
      { class: "page-head" },
      el("div", { class: "breadcrumb" }, el("button", { type: "button", onclick: () => (location.hash = "#/projects") }, "Projects"), " / ", project.slug),
    ),
    tabs,
    actions,
    secretsSection,
    credentialsSection,
    consoleCard,
    info,
  );
}

export function openProjectDialog(project = null) {
  const editing = Boolean(project);
  const slug = el("input", { value: project?.slug || "", disabled: editing, placeholder: "my-app" });
  const name = el("input", { value: project?.name || "", placeholder: "My App" });
  const path = el("input", { value: project?.path || "", placeholder: "/home/you/projects/my-app" });
  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Slug"), slug),
    el("div", { class: "field" }, el("label", {}, "Name"), name),
    el("div", { class: "field" }, el("label", {}, "Absolute directory"), path),
    editing ? null : el("p", { class: "note info" }, "The path must exist on the local server; the console only runs inside it."),
  );
  openModal({
    title: editing ? "Edit project" : "New project",
    body,
    submitLabel: editing ? "Save" : "Create",
    onSubmit: async () => {
      if (!slug.value.trim() || !name.value.trim() || !path.value.trim()) {
        toast("Fill in slug, name and directory", "error");
        return false;
      }
      if (editing) {
        await api(`/v1/projects/${project.id}`, {
          method: "PATCH",
          body: { name: name.value.trim(), path: path.value.trim() },
        });
        toast("Project updated");
        await renderProject(project.id);
      } else {
        const created = await api("/v1/projects", {
          method: "POST",
          body: { slug: slug.value.trim(), name: name.value.trim(), path: path.value.trim() },
        });
        toast("Project created");
        location.hash = `#/projects/${created.id}`;
      }
      return true;
    },
  });
}

export function openDeleteProject(project) {
  const input = el("input", { placeholder: project.slug });
  openModal({
    title: "Delete project",
    danger: true,
    submitLabel: "Delete permanently",
    body: el(
      "div",
      { class: "stack" },
      el("p", {}, `This deletes ${project.slug} and all its secrets and tokens. This cannot be undone.`),
      el("div", { class: "field" }, el("label", {}, `Type "${project.slug}" to confirm`), input),
    ),
    onSubmit: async () => {
      if (input.value !== project.slug) {
        toast("The slug does not match", "error");
        return false;
      }
      await api(`/v1/projects/${project.id}`, {
        method: "DELETE",
        body: { confirm_slug: project.slug },
      });
      toast("Project deleted");
      state.project = null;
      location.hash = "#/projects";
      return true;
    },
  });
}
