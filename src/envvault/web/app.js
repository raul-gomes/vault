/* EnvVault dashboard — no innerHTML, no external dependencies. */

const state = {
  csrf: null,
  version: "",
  view: "overview",
  projects: [],
  project: null,
  environment: null,
  secrets: [],
  credentials: [],
  projectCredentials: [],
  credentialFilter: { query: "", category: "", project: "" },
  auditFilter: { project: "", action: "", limit: 100 },
  execAbort: null,
};

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

const $id = (id) => document.getElementById(id);
const view = () => $id("view");
const dialog = () => $id("modal");

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

async function api(path, options = {}) {
  const { method = "GET", body, raw = false } = options;
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (state.csrf && method !== "GET" && method !== "HEAD") {
    headers["x-csrf-token"] = state.csrf;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 || response.status === 423) {
    showLogin(
      response.status === 423
        ? "O cofre foi bloqueado por inatividade. Entre novamente."
        : "Sessão expirada. Entre novamente.",
    );
    throw new ApiError("não autenticado", response.status);
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = await response.json();
      if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
      } else if (payload.detail) {
        detail = payload.detail;
      }
    } catch {
      /* keep statusText */
    }
    throw new ApiError(detail, response.status);
  }
  if (raw) return response;
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}

function toast(message, kind = "ok") {
  const node = $id("toast");
  node.textContent = message;
  node.className = `toast ${kind === "error" ? "error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.add("hidden"), 4200);
}

function fmtDate(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

function badge(text, kind = "") {
  return el("span", { class: `badge ${kind}` }, text);
}

function showLogin(message = "") {
  state.csrf = null;
  state.execAbort?.abort();
  $id("shell").classList.add("hidden");
  $id("login-view").classList.remove("hidden");
  $id("login-error").textContent = message;
  $id("passphrase").value = "";
  setTimeout(() => $id("passphrase").focus(), 40);
}

function showShell() {
  $id("login-view").classList.add("hidden");
  $id("shell").classList.remove("hidden");
  $id("sidebar-version").textContent = `v${state.version}`;
  route();
}

function setHeader(title, subtitle, actions = []) {
  $id("view-title").textContent = title;
  $id("view-subtitle").textContent = subtitle || "";
  const container = $id("topbar-actions");
  container.replaceChildren();
  for (const action of actions) {
    const button = el(
      "button",
      {
        class: `btn ${action.primary ? "primary" : ""} ${action.danger ? "danger" : ""}`,
        type: "button",
      },
      action.label,
    );
    button.addEventListener("click", action.onClick);
    container.append(button);
  }
}

function setActiveNav(name) {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === name);
  });
}

function loading() {
  view().replaceChildren(el("p", { class: "muted" }, "Carregando…"));
}

function section(title, children, actions = []) {
  const head = el(
    "div",
    { class: "section-title" },
    el("h3", {}, title),
    actions.length ? el("div", { class: "row" }, ...actions) : el("span"),
  );
  return el("div", { class: "card stack" }, head, ...children);
}

function metricCard(label, value, hint) {
  return el(
    "div",
    { class: "card" },
    el("div", { class: "card-title" }, label),
    el("div", { class: "metric" }, String(value)),
    hint ? el("p", { class: "muted" }, hint) : null,
  );
}

function table(headers, rows, options = {}) {
  const thead = el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h))));
  const tbody = el(
    "tbody",
    {},
    ...rows.map((cells) => {
      const tr = el(
        "tr",
        {},
        ...cells.map((cell) => el("td", {}, cell instanceof Node ? cell : String(cell ?? "—"))),
      );
      if (options.onRowClick) {
        tr.classList.add("clickable-row");
        tr.addEventListener("click", () => options.onRowClick(tr));
      }
      return tr;
    }),
  );
  return el("div", { class: "table-wrap" }, el("table", {}, thead, tbody));
}

function emptyState(title, description, actionLabel, action) {
  return el(
    "div",
    { class: "empty" },
    el("strong", {}, title),
    el("p", {}, description),
    actionLabel
      ? el("p", { class: "row", style: "justify-content:center;margin-top:14px" },
          el("button", { class: "btn primary", type: "button", onclick: action }, actionLabel))
      : null,
  );
}

// ---------------------------------------------------------------------------
// modals
// ---------------------------------------------------------------------------
function openModal({ title, body, submitLabel = "Salvar", danger = false, hideCancel = false, onSubmit }) {
  const node = dialog();
  $id("modal-title").textContent = title;
  $id("modal-body").replaceChildren(body);
  const submit = $id("modal-submit");
  const cancel = $id("modal-cancel");
  submit.textContent = submitLabel;
  submit.className = `btn ${danger ? "danger" : "primary"}`;
  submit.classList.toggle("hidden", submitLabel === null);
  cancel.classList.toggle("hidden", hideCancel);
  submit.onclick = async () => {
    if (!onSubmit) {
      node.close();
      return;
    }
    submit.disabled = true;
    try {
      const result = await onSubmit();
      if (result !== false) node.close();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      submit.disabled = false;
    }
  };
  if (!node.open) node.showModal();
  setTimeout(() => {
    const target = $id("modal-body").querySelector("input, textarea, select");
    target?.focus();
  }, 40);
}

function askPassphrase(title, description) {
  return new Promise((resolve) => {
    let settled = false;
    const input = el("input", {
      type: "password",
      autocomplete: "current-password",
      placeholder: "••••••••••••",
    });
    const node = dialog();
    const onClose = () => {
      node.removeEventListener("close", onClose);
      if (!settled) {
        settled = true;
        resolve(null);
      }
    };
    node.addEventListener("close", onClose);
    openModal({
      title,
      body: el(
        "div",
        { class: "stack" },
        el("p", { class: "muted" }, description),
        el("div", { class: "field" }, el("label", {}, "Passphrase"), input),
      ),
      submitLabel: "Confirmar",
      onSubmit: () => {
        if (!input.value) {
          toast("Informe a passphrase", "error");
          return false;
        }
        settled = true;
        resolve(input.value);
        return true;
      },
    });
  });
}

function showIssues(issues) {
  if (!issues.length) return;
  const list = el(
    "div",
    { class: "stack" },
    ...issues.map((issue) =>
      el(
        "div",
        { class: issue.level === "warning" ? "note" : "note" },
        `Linha ${issue.line}: ${issue.message}`,
      ),
    ),
  );
  openModal({
    title: "Avisos do .env",
    body: list,
    submitLabel: "Entendi",
    hideCancel: true,
  });
}

// ---------------------------------------------------------------------------
// login and routing
// ---------------------------------------------------------------------------
$id("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $id("login-btn");
  button.disabled = true;
  $id("login-error").textContent = "";
  try {
    const response = await fetch("/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ passphrase: $id("passphrase").value }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "Falha ao desbloquear");
    state.csrf = payload.csrf_token;
    state.version = payload.version || state.version;
    $id("passphrase").value = "";
    showShell();
  } catch (error) {
    $id("login-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    location.hash = `#/${button.dataset.view}`;
  });
});

$id("lock-btn").addEventListener("click", async () => {
  try {
    await api("/v1/auth/lock", { method: "POST" });
    showLogin("Cofre bloqueado.");
  } catch (error) {
    if (error.status !== 401) toast(error.message, "error");
  }
});

$id("modal-close").addEventListener("click", () => dialog().close());
$id("modal-cancel").addEventListener("click", () => dialog().close());
$id("modal-body").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
    event.preventDefault();
    $id("modal-submit").click();
  }
});

window.addEventListener("hashchange", () => route());

async function bootstrap() {
  try {
    const response = await fetch("/v1/session", { credentials: "same-origin" });
    const payload = await response.json();
    state.version = payload.version || "";
    if (payload.authenticated) {
      state.csrf = payload.csrf_token;
      showShell();
    } else {
      showLogin(
        payload.initialized === false
          ? "Cofre ainda não inicializado. Rode `envvault init` no terminal."
          : "",
      );
    }
  } catch {
    showLogin("Daemon indisponível. Rode `envvault serve` ou `envvault init`.");
  }
}

async function route() {
  state.execAbort?.abort();
  const hash = location.hash.replace(/^#\/?/, "") || "overview";
  const [name, id] = hash.split("/");
  const visible = ["overview", "projects", "credentials", "tokens", "audit", "settings"].includes(name)
    ? name
    : "overview";
  setActiveNav(visible);
  if ($id("shell").classList.contains("hidden")) return;
  loading();
  try {
    if (name === "projects" && id) {
      setActiveNav("projects");
      await renderProject(id);
    } else if (name === "projects") {
      await renderProjects();
    } else if (name === "credentials") {
      await renderCredentials();
    } else if (name === "tokens") {
      await renderTokens();
    } else if (name === "audit") {
      await renderAudit();
    } else if (name === "settings") {
      await renderSettings();
    } else {
      await renderOverview();
    }
  } catch (error) {
    if (error.status === 401 || error.status === 423) return;
    view().replaceChildren(el("div", { class: "note" }, error.message));
    toast(error.message, "error");
  }
}

// ---------------------------------------------------------------------------
// overview
// ---------------------------------------------------------------------------
async function renderOverview() {
  setHeader("Visão geral", "O que está no cofre e o que aconteceu recentemente.", [
    { label: "Atualizar", onClick: renderOverview },
    { label: "Novo projeto", primary: true, onClick: () => openProjectDialog() },
  ]);
  const data = await api("/v1/overview");
  const status = data.status;
  const cards = el(
    "div",
    { class: "grid" },
    metricCard("Projetos", data.projects, "diretórios registrados"),
    metricCard("Segredos", data.secrets, "valores criptografados"),
    metricCard("Ambientes", data.environments, "dev, prod, staging…"),
    metricCard("Credenciais", data.credentials, "serviços externos"),
    metricCard("Tokens ativos", data.active_tokens, "acesso de agentes"),
  );
  const statusCard = el(
    "div",
    { class: "card stack" },
    el("div", { class: "row" }, el("h3", {}, "Estado do cofre"), badge(status.unlocked ? "desbloqueado" : "bloqueado", status.unlocked ? "ok" : "warn")),
    el(
      "dl",
      { class: "kv" },
      el("dt", {}, "Banco"),
      el("dd", {}, data.paths.database),
      el("dt", {}, "Timeout"),
      el("dd", {}, `${status.lock_timeout_minutes} min de inatividade`),
      el("dt", {}, "Versão"),
      el("dd", {}, data.version),
    ),
    el(
      "p",
      { class: "muted" },
      "O Claude recebe apenas o resultado redigido dos comandos. Valores só saem do cofre em reveal/export, sempre auditados.",
    ),
  );
  const recent = data.recent_audit.length
    ? table(
        ["quando", "ator", "ação", "projeto", "resultado"],
        data.recent_audit.map((entry) => [
          fmtDate(entry.ts),
          `${entry.actor_type}:${entry.actor_name}`,
          entry.action,
          entry.project_slug || "—",
          badge(entry.result, entry.result === "ok" ? "ok" : "err"),
        ]),
      )
    : el("p", { class: "muted" }, "Nenhum evento ainda.");
  view().replaceChildren(
    cards,
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1.2fr 1fr;align-items:start" },
      statusCard,
      section("Atividade recente", [recent]),
    ),
  );
}

// ---------------------------------------------------------------------------
// projects
// ---------------------------------------------------------------------------
async function loadProjects() {
  const data = await api("/v1/projects");
  state.projects = data.items;
  return state.projects;
}

async function renderProjects() {
  setHeader("Projetos", "Cada projeto tem um diretório e ambientes independentes.", [
    { label: "Atualizar", onClick: renderProjects },
    { label: "Novo projeto", primary: true, onClick: () => openProjectDialog() },
  ]);
  const projects = await loadProjects();
  if (!projects.length) {
    view().replaceChildren(
      emptyState(
        "Nenhum projeto ainda",
        "Registre o diretório de um repositório para importar ou criar segredos.",
        "Registrar primeiro projeto",
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
      "Abrir",
    ),
  ]);
  view().replaceChildren(
    table(["slug", "nome", "diretório", "segredos", "ambientes", ""], rows, {
      onRowClick: (tr) => {
        const index = Array.from(tr.parentNode.children).indexOf(tr);
        location.hash = `#/projects/${projects[index].id}`;
      },
    }),
  );
}

async function loadProjectCredentials(projectId) {
  const [scoped, globals] = await Promise.all([
    api(`/v1/credentials?project_id=${encodeURIComponent(projectId)}`),
    api("/v1/credentials?global_only=true"),
  ]);
  return [...scoped.items, ...globals.items];
}

async function refreshProject() {
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

async function renderProject(id) {
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

function renderProjectPage() {
  const project = state.project;
  const envs = project.environments.map((item) => item.environment);
  if (!envs.includes(state.environment)) envs.unshift(state.environment);
  const env = state.environment;
  setHeader(project.name, `${project.slug} · ${project.path}`, [
    { label: "Credenciais", onClick: () => {
        state.credentialFilter = { query: "", category: "", project: project.id };
        location.hash = "#/credentials";
      } },
    { label: "Editar", onClick: () => openProjectDialog(project) },
    { label: "Excluir", danger: true, onClick: () => openDeleteProject(project) },
    { label: "Atualizar", onClick: refreshProject },
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
          const name = await promptText("Novo ambiente", "Nome curto, ex.: staging", "staging");
          if (!name) return;
          const normalized = name.trim().toLowerCase();
          try {
            await api(`/v1/projects/${project.id}/environments`, {
              method: "POST",
              body: { name: normalized },
            });
            state.environment = normalized;
            await refreshProject();
            toast(`Ambiente ${normalized} pronto.`);
          } catch (error) {
            toast(error.message, "error");
          }
        },
      },
      "+ ambiente",
    ),
  );

  const actions = el(
    "div",
    { class: "row" },
    el("button", { class: "btn primary", type: "button", onclick: () => openSecretDialog(project, env) }, "Novo segredo"),
    el("button", { class: "btn", type: "button", onclick: () => openImportDialog(project, env) }, "Importar .env"),
    el("button", { class: "btn", type: "button", onclick: () => openExportDialog(project, env) }, "Exportar .env"),
  );

  const rows = state.secrets.map((secret) => [
    el("span", { class: "mono" }, secret.key),
    el("span", { class: "tag" }, `v${secret.version}`),
    fmtDate(secret.updated_at),
    el(
      "div",
      { class: "row" },
      el("button", { class: "btn small", type: "button", onclick: () => openRevealDialog(project, env, secret) }, "Revelar"),
      el("button", { class: "btn small", type: "button", onclick: () => openSecretDialog(project, env, secret) }, "Editar"),
      el("button", { class: "btn small danger", type: "button", onclick: () => openDeleteSecret(project, env, secret) }, "Excluir"),
    ),
  ]);

  const secretsSection = state.secrets.length
    ? table(["chave", "versão", "atualizado", ""], rows)
    : emptyState(
        `Nenhum segredo em ${env}`,
        "Adicione manualmente, gere uma senha ou importe um arquivo .env.",
        "Adicionar segredo",
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
    el("p", { class: "muted" }, `Diretório: ${project.path}`),
    el(
      "p",
      { class: "muted" },
      "A injeção acontece dentro do daemon. O processo filho recebe as variáveis; a saída é redigida antes de voltar para a tela ou para o agente.",
    ),
  );

  view().replaceChildren(
    el(
      "div",
      { class: "page-head" },
      el("div", { class: "breadcrumb" }, el("button", { type: "button", onclick: () => (location.hash = "#/projects") }, "Projetos"), " / ", project.slug),
    ),
    tabs,
    actions,
    secretsSection,
    credentialsSection,
    consoleCard,
    info,
  );
}

function buildProjectCredentials(project) {
  const own = state.projectCredentials.filter((item) => item.scope === "project");
  const globals = state.projectCredentials.filter((item) => item.scope === "global");

  const ownRows = own.map((credential) => [
    el("span", { class: "mono" }, credential.name),
    el("span", { class: "tag" }, credentialCategoryLabel(credential.category)),
    el("span", { class: "tag" }, `v${credential.version}`),
    fmtDate(credential.updated_at),
    el(
      "div",
      { class: "row" },
      el(
        "button",
        { class: "btn small", type: "button", onclick: () => openRevealCredential(credential) },
        "Revelar",
      ),
      el(
        "button",
        { class: "btn small", type: "button", onclick: () => openCredentialDialog(credential) },
        "Editar",
      ),
      el(
        "button",
        { class: "btn small danger", type: "button", onclick: () => openDeleteCredential(credential) },
        "Excluir",
      ),
    ),
  ]);

  const ownContent = own.length
    ? table(["nome", "categoria", "versão", "atualizado", ""], ownRows)
    : el(
        "p",
        { class: "muted" },
        "Nenhuma credencial específica deste projeto. As globais abaixo também ficam disponíveis aqui.",
      );

  const globalRows = globals.map((credential) => [
    el("span", { class: "mono" }, credential.name),
    el("span", { class: "tag" }, credentialCategoryLabel(credential.category)),
    el("span", { class: "tag" }, `v${credential.version}`),
    el(
      "button",
      { class: "btn small", type: "button", onclick: () => openRevealCredential(credential) },
      "Revelar",
    ),
  ]);

  const children = [
    el(
      "div",
      { class: "row" },
      el(
        "button",
        {
          class: "btn primary small",
          type: "button",
          onclick: () => openCredentialDialog(null, project),
        },
        "Nova credencial deste projeto",
      ),
      el(
        "button",
        {
          class: "btn small",
          type: "button",
          onclick: () => {
            state.credentialFilter = { query: "", category: "", project: project.id };
            location.hash = "#/credentials";
          },
        },
        "Gerenciar todas",
      ),
    ),
    ownContent,
  ];

  if (globals.length) {
    children.push(
      el("p", { class: "muted" }, "Credenciais globais disponíveis neste projeto"),
      table(["nome", "categoria", "versão", ""], globalRows),
    );
  }

  return section("Credenciais do projeto", children);
}

function buildConsole(project, env) {
  const command = el("input", { id: "exec-command", placeholder: "npm run dev", autocomplete: "off" });
  const cwd = el("input", { id: "exec-cwd", placeholder: project.path, autocomplete: "off" });
  const output = el("pre", { id: "exec-output", class: "output" });
  const runButton = el("button", { class: "btn primary", type: "button" }, "Executar");
  const stopButton = el("button", { class: "btn danger", type: "button", disabled: true }, "Parar");
  const note = el("p", { class: "muted" }, "A saída passa pelo redator de segredos. Comandos são auditados.");

  runButton.addEventListener("click", async () => {
    const argv = splitCommand(command.value.trim());
    if (!argv.length) {
      toast("Informe um comando", "error");
      return;
    }
    runButton.disabled = true;
    stopButton.disabled = false;
    output.textContent = "";
    const controller = new AbortController();
    state.execAbort = controller;
    try {
      const response = await fetch("/v1/exec", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "x-csrf-token": state.csrf },
        body: JSON.stringify({
          project_id: project.id,
          environment: env,
          command: argv,
          cwd: cwd.value.trim() || null,
        }),
        signal: controller.signal,
      });
      if (response.status === 401 || response.status === 423) {
        showLogin("Sessão expirada. Entre novamente.");
        return;
      }
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new ApiError(payload.detail || "Falha ao executar", response.status);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let index = buffer.indexOf("\n\n");
        while (index >= 0) {
          handleSseFrame(buffer.slice(0, index), output);
          buffer = buffer.slice(index + 2);
          index = buffer.indexOf("\n\n");
        }
      }
    } catch (error) {
      if (error.name === "AbortError") toast("Execução cancelada.");
      else toast(error.message, "error");
    } finally {
      state.execAbort = null;
      runButton.disabled = false;
      stopButton.disabled = true;
    }
  });

  stopButton.addEventListener("click", () => {
    state.execAbort?.abort();
    state.execAbort = null;
    stopButton.disabled = true;
    runButton.disabled = false;
  });

  return el(
    "div",
    { class: "card stack" },
    el("div", { class: "section-title" }, el("h3", {}, `Console · ${env}`), el("span", { class: "tag" }, project.slug)),
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1.4fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Comando (argv, sem shell)"), command),
      el("div", { class: "field" }, el("label", {}, "Diretório (dentro do projeto)"), cwd),
    ),
    el("div", { class: "row" }, runButton, stopButton, el("div", { class: "spacer" }), note),
    output,
  );
}

function handleSseFrame(frame, output) {
  for (const line of frame.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    let event;
    try {
      event = JSON.parse(line.slice(6));
    } catch {
      continue;
    }
    if (event.type === "output") {
      output.textContent += event.text;
      output.scrollTop = output.scrollHeight;
    } else if (event.type === "exit") {
      const ok = event.code === 0;
      toast(ok ? "Comando finalizado (código 0)." : `Comando saiu com código ${event.code}.`, ok ? "ok" : "error");
    }
  }
}

function splitCommand(line) {
  const parts = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = pattern.exec(line))) {
    parts.push(match[1] ?? match[2] ?? match[3]);
  }
  return parts;
}

// ---------------------------------------------------------------------------
// project dialogs
// ---------------------------------------------------------------------------
function openProjectDialog(project = null) {
  const editing = Boolean(project);
  const slug = el("input", { value: project?.slug || "", disabled: editing, placeholder: "meu-app" });
  const name = el("input", { value: project?.name || "", placeholder: "Meu App" });
  const path = el("input", { value: project?.path || "", placeholder: "/home/voce/projetos/meu-app" });
  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Slug"), slug),
    el("div", { class: "field" }, el("label", {}, "Nome"), name),
    el("div", { class: "field" }, el("label", {}, "Diretório absoluto"), path),
    editing ? null : el("p", { class: "note info" }, "O caminho precisa existir no servidor local; o console só executa dentro dele."),
  );
  openModal({
    title: editing ? "Editar projeto" : "Novo projeto",
    body,
    submitLabel: editing ? "Salvar" : "Criar",
    onSubmit: async () => {
      if (!slug.value.trim() || !name.value.trim() || !path.value.trim()) {
        toast("Preencha slug, nome e diretório", "error");
        return false;
      }
      if (editing) {
        await api(`/v1/projects/${project.id}`, {
          method: "PATCH",
          body: { name: name.value.trim(), path: path.value.trim() },
        });
        toast("Projeto atualizado");
        await renderProject(project.id);
      } else {
        const created = await api("/v1/projects", {
          method: "POST",
          body: { slug: slug.value.trim(), name: name.value.trim(), path: path.value.trim() },
        });
        toast("Projeto criado");
        location.hash = `#/projects/${created.id}`;
      }
      return true;
    },
  });
}

function openDeleteProject(project) {
  const input = el("input", { placeholder: project.slug });
  openModal({
    title: "Excluir projeto",
    danger: true,
    submitLabel: "Excluir definitivamente",
    body: el(
      "div",
      { class: "stack" },
      el("p", {}, `Isso apaga ${project.slug}, todos os segredos e tokens. Não há desfazer.`),
      el("div", { class: "field" }, el("label", {}, `Digite "${project.slug}" para confirmar`), input),
    ),
    onSubmit: async () => {
      if (input.value !== project.slug) {
        toast("O slug não confere", "error");
        return false;
      }
      await api(`/v1/projects/${project.id}`, {
        method: "DELETE",
        body: { confirm_slug: project.slug },
      });
      toast("Projeto excluído");
      state.project = null;
      location.hash = "#/projects";
      return true;
    },
  });
}

function promptText(title, description, placeholder = "") {
  return new Promise((resolve) => {
    let settled = false;
    const input = el("input", { placeholder });
    const node = dialog();
    const onClose = () => {
      node.removeEventListener("close", onClose);
      if (!settled) {
        settled = true;
        resolve(null);
      }
    };
    node.addEventListener("close", onClose);
    openModal({
      title,
      body: el("div", { class: "stack" }, el("p", { class: "muted" }, description), input),
      submitLabel: "Confirmar",
      onSubmit: () => {
        if (!input.value.trim()) return false;
        settled = true;
        resolve(input.value.trim());
        return true;
      },
    });
  });
}

// ---------------------------------------------------------------------------
// secret dialogs
// ---------------------------------------------------------------------------
function openSecretDialog(project, environment, secret = null) {
  const editing = Boolean(secret);
  const key = el("input", {
    value: secret?.key || "",
    disabled: editing,
    placeholder: "DATABASE_URL",
    autocomplete: "off",
  });
  const value = el("input", {
    type: "password",
    placeholder: editing ? "novo valor (o atual não é exibido)" : "valor do segredo",
    autocomplete: "new-password",
  });
  const reveal = el("button", { class: "btn small", type: "button" }, "Mostrar");
  reveal.addEventListener("click", () => {
    const hidden = value.type === "password";
    value.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Ocultar" : "Mostrar";
  });

  const length = el("input", { type: "number", min: "8", max: "256", value: "32", style: "width:90px" });
  const upper = el("input", { type: "checkbox", checked: true });
  const lower = el("input", { type: "checkbox", checked: true });
  const digits = el("input", { type: "checkbox", checked: true });
  const symbols = el("input", { type: "checkbox", checked: true });
  const entropy = el("span", { class: "muted" }, "");
  const generate = el("button", { class: "btn small", type: "button" }, "Gerar senha");
  generate.addEventListener("click", async () => {
    generate.disabled = true;
    try {
      const data = await api("/v1/generate", {
        method: "POST",
        body: {
          length: Number(length.value),
          upper: upper.checked,
          lower: lower.checked,
          digits: digits.checked,
          symbols: symbols.checked,
        },
      });
      value.type = "text";
      reveal.textContent = "Ocultar";
      value.value = data.password;
      entropy.textContent = `~${data.entropy_bits} bits · ${data.alphabet_size} símbolos`;
    } catch (error) {
      toast(error.message, "error");
    } finally {
      generate.disabled = false;
    }
  });

  const generator = el(
    "div",
    { class: "card stack", style: "padding:14px;background:var(--panel-2)" },
    el("div", { class: "row" }, el("strong", {}, "Gerador embutido"), el("div", { class: "spacer" }), generate),
    el(
      "div",
      { class: "row" },
      el("label", { class: "field-inline" }, "Tamanho", length),
      el("label", { class: "field-inline" }, upper, "A-Z"),
      el("label", { class: "field-inline" }, lower, "a-z"),
      el("label", { class: "field-inline" }, digits, "0-9"),
      el("label", { class: "field-inline" }, symbols, "símbolos"),
      entropy,
    ),
  );

  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Chave"), key),
    el(
      "div",
      { class: "field" },
      el("label", {}, editing ? "Novo valor" : "Valor"),
      el("div", { class: "row" }, value, reveal),
    ),
    editing ? null : generator,
    el("p", { class: "note info" }, "O valor é criptografado antes de tocar o SQLite. Ele só sai do cofre em reveal ou export, ambos auditados."),
  );

  openModal({
    title: `${editing ? "Editar" : "Novo"} segredo · ${project.slug}/${environment}`,
    body,
    submitLabel: editing ? "Atualizar" : "Salvar",
    onSubmit: async () => {
      if (!key.value.trim() || !value.value) {
        toast("Preencha chave e valor", "error");
        return false;
      }
      await api(`/v1/projects/${project.id}/secrets`, {
        method: "PUT",
        body: { environment, key: key.value.trim(), value: value.value },
      });
      toast(editing ? "Segredo atualizado" : "Segredo criado");
      state.environment = environment;
      await refreshProject();
      return true;
    },
  });
}

function openDeleteSecret(project, environment, secret) {
  openModal({
    title: "Excluir segredo",
    danger: true,
    submitLabel: "Excluir",
    body: el("p", {}, `Remover ${secret.key} de ${project.slug}/${environment}? Esta ação não pode ser desfeita.`),
    onSubmit: async () => {
      await api(
        `/v1/projects/${project.id}/secrets/${encodeURIComponent(secret.key)}?environment=${encodeURIComponent(environment)}`,
        { method: "DELETE" },
      );
      toast("Segredo excluído");
      await refreshProject();
      return true;
    },
  });
}

async function openRevealDialog(project, environment, secret) {
  const passphrase = await askPassphrase(
    `Revelar ${secret.key}`,
    "A passphrase é revalidada e o acesso fica registrado na auditoria.",
  );
  if (!passphrase) return;
  try {
    const data = await api(`/v1/projects/${project.id}/secrets/${encodeURIComponent(secret.key)}/reveal`, {
      method: "POST",
      body: { environment, passphrase },
    });
    const code = el("div", { class: "code-block" }, data.value);
    const copy = el("button", { class: "btn small", type: "button" }, "Copiar");
    copy.addEventListener("click", () => copyText(data.value));
    const timerLabel = el("span", { class: "muted" }, "oculta em 60s");
    const timer = setTimeout(() => {
      code.textContent = "•••••••• (valor ocultado)";
      copy.disabled = true;
      timerLabel.textContent = "valor ocultado";
    }, 60000);
    dialog().addEventListener("close", () => clearTimeout(timer), { once: true });
    openModal({
      title: `${secret.key} · ${environment}`,
      body: el(
        "div",
        { class: "stack" },
        el("p", { class: "note" }, "Não cole este valor em conversas, issues ou logs. Se ele aparecer em algum lugar, rotacione."),
        code,
        el("div", { class: "row" }, copy, timerLabel),
      ),
      submitLabel: "Fechar",
      hideCancel: true,
    });
  } catch (error) {
    toast(error.message, "error");
  }
}

function openImportDialog(project, environment) {
  const file = el("input", { type: "file", accept: ".env,.txt,text/plain" });
  const text = el("textarea", { rows: "8", placeholder: "ou cole aqui o conteúdo do .env" });
  const target = el("input", { value: environment });
  const replace = el("input", { type: "checkbox" });
  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Arquivo .env"), file),
    el("div", { class: "field" }, el("label", {}, "Conteúdo"), text),
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Ambiente de destino"), target),
      el("label", { class: "field-inline", style: "align-self:end;padding-bottom:9px" }, replace, "Sobrescrever chaves existentes"),
    ),
    el("p", { class: "note info" }, "O parser aceita comentários, export, aspas simples/duplas e nunca executa o conteúdo."),
  );
  openModal({
    title: `Importar .env · ${project.slug}`,
    body,
    submitLabel: "Importar",
    onSubmit: async () => {
      let content = text.value;
      if (file.files?.length) content = await file.files[0].text();
      if (!content.trim()) {
        toast("Selecione um arquivo ou cole o conteúdo", "error");
        return false;
      }
      const result = await api(`/v1/projects/${project.id}/import`, {
        method: "POST",
        body: {
          environment: target.value.trim().toLowerCase(),
          content,
          replace: replace.checked,
        },
      });
      toast(
        `${result.created} criados, ${result.updated} atualizados, ${result.skipped} ignorados`,
      );
      state.environment = target.value.trim().toLowerCase();
      await refreshProject();
      if (result.issues.length) setTimeout(() => showIssues(result.issues), 150);
      return true;
    },
  });
}

async function openExportDialog(project, environment) {
  const passphrase = await askPassphrase(
    `Exportar ${project.slug}/${environment}`,
    "Será gerado um .env temporário. Prefira `envvault run` para não deixar valores em disco.",
  );
  if (!passphrase) return;
  try {
    const text = await api(`/v1/projects/${project.id}/export`, {
      method: "POST",
      body: { environment, passphrase },
    });
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: `${project.slug}.${environment}.env` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast("Arquivo exportado. Apague-o depois de usar.");
  } catch (error) {
    toast(error.message, "error");
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copiado para a área de transferência.");
  } catch {
    toast("Não foi possível copiar", "error");
  }
}

// ---------------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------------
const CREDENTIAL_CATEGORIES = [
  ["hosting", "Hospedagem"],
  ["dns", "DNS / domínios"],
  ["email", "E-mail"],
  ["smtp", "SMTP / envio"],
  ["api", "API / token"],
  ["database", "Banco de dados"],
  ["other", "Outra"],
];

function credentialCategoryLabel(value) {
  const found = CREDENTIAL_CATEGORIES.find(([slug]) => slug === value);
  return found ? found[1] : value;
}

async function refreshCredentialViews() {
  if (state.project && location.hash.startsWith("#/projects/")) {
    await refreshProject();
  } else {
    await renderCredentials();
  }
}

async function renderCredentials() {
  setHeader(
    "Credenciais",
    "Logins de serviços externos, globais ou por projeto (cliente). Os campos sensíveis só saem do cofre em reveal auditado.",
    [
      { label: "Atualizar", onClick: renderCredentials },
      { label: "Nova credencial", primary: true, onClick: () => openCredentialDialog() },
    ],
  );
  if (!state.projects.length) await loadProjects();
  const filter = state.credentialFilter;
  const query = el("input", {
    value: filter.query,
    placeholder: "buscar por nome ou categoria",
    autocomplete: "off",
  });
  const category = el(
    "select",
    {},
    el("option", { value: "" }, "todas as categorias"),
    ...CREDENTIAL_CATEGORIES.map(([slug, label]) => el("option", { value: slug }, label)),
  );
  category.value = filter.category;
  const project = el(
    "select",
    {},
    el("option", { value: "" }, "todos os escopos"),
    el("option", { value: "__global__" }, "somente globais"),
    ...state.projects.map((item) =>
      el("option", { value: item.id }, `projeto: ${item.slug}`),
    ),
  );
  project.value = filter.project;
  const apply = el("button", { class: "btn", type: "button" }, "Filtrar");
  apply.addEventListener("click", () => {
    state.credentialFilter = {
      query: query.value.trim(),
      category: category.value,
      project: project.value,
    };
    renderCredentials();
  });
  query.addEventListener("keydown", (event) => {
    if (event.key === "Enter") apply.click();
  });

  const params = new URLSearchParams();
  if (filter.query) params.set("query", filter.query);
  if (filter.category) params.set("category", filter.category);
  if (filter.project === "__global__") params.set("global_only", "true");
  else if (filter.project) params.set("project_id", filter.project);
  const data = await api(`/v1/credentials?${params.toString()}`);
  state.credentials = data.items;

  const rows = data.items.map((credential) => [
    el("span", { class: "mono" }, credential.name),
    el("span", { class: "tag" }, credentialCategoryLabel(credential.category)),
    credential.project
      ? el("span", { class: "tag" }, credential.project.slug)
      : badge("global", "ok"),
    el("span", { class: "tag" }, `v${credential.version}`),
    fmtDate(credential.updated_at),
    el(
      "div",
      { class: "row" },
      el(
        "button",
        { class: "btn small", type: "button", onclick: () => openRevealCredential(credential) },
        "Revelar",
      ),
      el(
        "button",
        { class: "btn small", type: "button", onclick: () => openCredentialDialog(credential) },
        "Editar",
      ),
      el(
        "button",
        { class: "btn small danger", type: "button", onclick: () => openDeleteCredential(credential) },
        "Excluir",
      ),
    ),
  ]);

  const content = data.items.length
    ? table(["nome", "categoria", "escopo", "versão", "atualizado", ""], rows)
    : emptyState(
        "Nenhuma credencial ainda",
        "Guarde logins de Hostinger, Cloudflare, Gmail, SMTP e outros serviços. Use o escopo global para o que é seu e o projeto para cada cliente.",
        "Adicionar credencial",
        () => openCredentialDialog(),
      );

  view().replaceChildren(
    el(
      "div",
      { class: "card row" },
      query,
      category,
      project,
      apply,
      el("div", { class: "spacer" }),
      el("span", { class: "muted" }, `${data.total} credenciais`),
    ),
    content,
    el(
      "p",
      { class: "note info" },
      "Nome, categoria e escopo ficam visíveis para busca. Usuário, senha, URL e notas são criptografados juntos e nunca aparecem em listagens. Tokens de agente não têm acesso a esta área.",
    ),
  );
}

async function openCredentialDialog(credential = null, defaultProject = null) {
  const editing = Boolean(credential);
  if (!state.projects.length) await loadProjects();
  let current = { username: "", password: "", url: "", notes: "" };
  if (editing) {
    const passphrase = await askPassphrase(
      `Editar ${credential.name}`,
      "Para editar os campos criptografados a passphrase é revalidada. O acesso fica na auditoria.",
    );
    if (!passphrase) return;
    try {
      current = await api(`/v1/credentials/${credential.id}/reveal`, {
        method: "POST",
        body: { passphrase },
      });
    } catch (error) {
      toast(error.message, "error");
      return;
    }
  }

  const name = el("input", { value: credential?.name || "", placeholder: "Hostinger" });
  const known = CREDENTIAL_CATEGORIES.some(([slug]) => slug === credential?.category);
  const categoryOptions = [...CREDENTIAL_CATEGORIES];
  if (credential?.category && !known) {
    categoryOptions.push([credential.category, credential.category]);
  }
  const category = el(
    "select",
    {},
    ...categoryOptions.map(([slug, label]) => el("option", { value: slug }, label)),
  );
  category.value = credential?.category || "hosting";
  const project = el(
    "select",
    {},
    el("option", { value: "" }, "Global (todos os projetos)"),
    ...state.projects.map((item) =>
      el("option", { value: item.id }, `Projeto: ${item.slug} — ${item.name}`),
    ),
  );
  project.value = credential?.project?.id || defaultProject?.id || "";
  const username = el("input", {
    value: current.username || "",
    placeholder: "usuario@exemplo.com",
    autocomplete: "off",
  });
  const password = el("input", {
    type: "password",
    value: current.password || "",
    placeholder: "senha ou token",
    autocomplete: "new-password",
  });
  const url = el("input", { value: current.url || "", placeholder: "https://painel.servico.com" });
  const notes = el("textarea", { rows: "4", placeholder: "observações, escopo do token, etc." });
  notes.value = current.notes || "";

  const reveal = el("button", { class: "btn small", type: "button" }, "Mostrar");
  reveal.addEventListener("click", () => {
    const hidden = password.type === "password";
    password.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Ocultar" : "Mostrar";
  });

  const length = el("input", {
    type: "number",
    min: "8",
    max: "256",
    value: "32",
    style: "width:90px",
  });
  const entropy = el("span", { class: "muted" }, "");
  const generate = el("button", { class: "btn small", type: "button" }, "Gerar senha");
  generate.addEventListener("click", async () => {
    generate.disabled = true;
    try {
      const data = await api("/v1/generate", {
        method: "POST",
        body: { length: Number(length.value) },
      });
      password.type = "text";
      reveal.textContent = "Ocultar";
      password.value = data.password;
      entropy.textContent = `~${data.entropy_bits} bits · ${data.alphabet_size} símbolos`;
    } catch (error) {
      toast(error.message, "error");
    } finally {
      generate.disabled = false;
    }
  });

  const body = el(
    "div",
    { class: "stack" },
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1.4fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Nome"), name),
      el("div", { class: "field" }, el("label", {}, "Categoria"), category),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Escopo"),
      project,
      el(
        "p",
        { class: "muted" },
        "Global = compartilhada por todos os projetos. Projeto = específica de um cliente.",
      ),
    ),
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Usuário / e-mail"), username),
      el("div", { class: "field" }, el("label", {}, "URL do painel"), url),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Senha / token"),
      el("div", { class: "row" }, password, reveal),
    ),
    el(
      "div",
      { class: "card stack", style: "padding:12px;background:var(--panel-2)" },
      el(
        "div",
        { class: "row" },
        el("strong", {}, "Gerador embutido"),
        el("label", { class: "field-inline" }, "Tamanho", length),
        generate,
        entropy,
      ),
    ),
    el("div", { class: "field" }, el("label", {}, "Notas"), notes),
    el(
      "p",
      { class: "note info" },
      "Usuário, senha, URL e notas são criptografados em um único payload AES-256-GCM. Apenas nome e categoria ficam visíveis.",
    ),
  );

  openModal({
    title: editing ? `Editar credencial · ${credential.name}` : "Nova credencial",
    body,
    submitLabel: editing ? "Salvar" : "Criar",
    onSubmit: async () => {
      if (!name.value.trim()) {
        toast("Informe um nome", "error");
        return false;
      }
      const payload = {
        name: name.value.trim(),
        category: category.value,
        username: username.value,
        password: password.value,
        url: url.value.trim(),
        notes: notes.value,
        project_id: project.value || null,
      };
      if (editing) {
        await api(`/v1/credentials/${credential.id}`, { method: "PUT", body: payload });
        toast("Credencial atualizada");
      } else {
        await api("/v1/credentials", { method: "POST", body: payload });
        toast("Credencial criada");
      }
      await refreshCredentialViews();
      return true;
    },
  });
}

async function openRevealCredential(credential) {
  const passphrase = await askPassphrase(
    `Revelar ${credential.name}`,
    "A passphrase é revalidada e o acesso fica registrado na auditoria.",
  );
  if (!passphrase) return;
  try {
    const data = await api(`/v1/credentials/${credential.id}/reveal`, {
      method: "POST",
      body: { passphrase },
    });
    const password = el("div", { class: "code-block" }, data.password || "(sem senha salva)");
    const copy = el("button", { class: "btn small", type: "button" }, "Copiar senha");
    copy.disabled = !data.password;
    copy.addEventListener("click", () => copyText(data.password));
    const timerLabel = el("span", { class: "muted" }, "oculta em 60s");
    const timer = setTimeout(() => {
      password.textContent = "•••••••• (senha ocultada)";
      copy.disabled = true;
      timerLabel.textContent = "senha ocultada";
    }, 60000);
    dialog().addEventListener("close", () => clearTimeout(timer), { once: true });

    const details = el(
      "dl",
      { class: "kv" },
      el("dt", {}, "Escopo"),
      el("dd", {}, data.project ? `projeto ${data.project.slug}` : "global"),
      el("dt", {}, "Categoria"),
      el("dd", {}, credentialCategoryLabel(data.category)),
      el("dt", {}, "Usuário"),
      el("dd", {}, data.username || "—"),
      el("dt", {}, "URL"),
      el("dd", {}, data.url || "—"),
      el("dt", {}, "Notas"),
      el("dd", {}, data.notes || "—"),
    );

    openModal({
      title: `${data.name} · v${data.version}`,
      body: el(
        "div",
        { class: "stack" },
        el(
          "p",
          { class: "note" },
          "Não cole estes valores em conversas, issues ou logs. Se aparecerem em algum lugar, rotacione.",
        ),
        details,
        el("div", { class: "field" }, el("label", {}, "Senha / token"), password),
        el("div", { class: "row" }, copy, timerLabel),
      ),
      submitLabel: "Fechar",
      hideCancel: true,
    });
  } catch (error) {
    toast(error.message, "error");
  }
}

function openDeleteCredential(credential) {
  openModal({
    title: "Excluir credencial",
    danger: true,
    submitLabel: "Excluir",
    body: el(
      "p",
      {},
      `Remover ${credential.name} (${credentialCategoryLabel(credential.category)})? Esta ação não pode ser desfeita.`,
    ),
    onSubmit: async () => {
      await api(`/v1/credentials/${credential.id}`, { method: "DELETE" });
      toast("Credencial excluída");
      await refreshCredentialViews();
      return true;
    },
  });
}

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------
async function renderTokens() {
  setHeader("Tokens", "Credenciais de agente com escopo restrito. Elas nunca podem revelar valores.", [
    { label: "Atualizar", onClick: renderTokens },
    { label: "Novo token", primary: true, onClick: () => openTokenDialog() },
  ]);
  const [tokens, projects] = await Promise.all([api("/v1/tokens"), loadProjects()]);
  const items = tokens.items;
  const rows = items.map((token) => [
    el("span", { class: "mono" }, token.name),
    token.project.slug,
    el("div", { class: "row" }, ...token.environments.map((env) => el("span", { class: "tag" }, env))),
    [
      token.can_list ? "listar" : null,
      token.can_inject ? "executar" : null,
    ].filter(Boolean).join(" · "),
    token.any_command
      ? el("span", { class: "badge warn" }, "qualquer comando")
      : token.allowed_commands.length
        ? el("span", { class: "mono muted" }, token.allowed_commands.join(", "))
        : el("span", { class: "badge err" }, token.can_inject ? "recriar (sem comandos)" : "—"),
    fmtDate(token.last_used_at),
    badge(token.active ? "ativo" : "revogado", token.active ? "ok" : "err"),
    token.active
      ? el(
          "button",
          {
            class: "btn small danger",
            type: "button",
            onclick: () => openRevokeToken(token),
          },
          "Revogar",
        )
      : el("span", { class: "muted" }, "—"),
  ]);
  const content = items.length
    ? table(
        ["nome", "projeto", "ambientes", "permissões", "comandos", "último uso", "status", ""],
        rows,
      )
    : emptyState(
        "Nenhum token criado",
        "Crie um token para o Claude executar comandos com segredos sem receber os valores.",
        "Criar token",
        () => openTokenDialog(),
      );
  view().replaceChildren(
    content,
    el(
      "p",
      { class: "note info" },
      "O token não dá acesso ao dashboard nem a reveal/export. Prefira restringir ambientes e prefixos de comando; um token sem restrição pode executar qualquer argv.",
    ),
  );
}

function openTokenDialog() {
  const projects = state.projects.length ? state.projects : [];
  if (!projects.length) {
    toast("Registre um projeto antes de criar tokens", "error");
    return;
  }
  const project = el(
    "select",
    {},
    ...projects.map((item) => el("option", { value: item.id }, `${item.slug} — ${item.name}`)),
  );
  const name = el("input", { value: "claude", placeholder: "claude-frontend" });
  const environments = el("input", { value: "dev", placeholder: "dev, staging" });
  const canList = el("input", { type: "checkbox", checked: true });
  const canInject = el("input", { type: "checkbox", checked: true });
  const anyCommand = el("input", { type: "checkbox" });
  const commands = el("textarea", {
    rows: "4",
    placeholder: "npm run dev\npytest\ndocker compose up",
  });
  const updateName = () => {
    const selected = projects.find((item) => item.id === project.value);
    if (!selected) return;
    name.value = `claude-${selected.slug}`;
    const envs = selected.environments.map((item) => item.environment);
    environments.value = envs.length ? envs.join(", ") : "dev";
  };
  project.addEventListener("change", updateName);
  updateName();
  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Projeto"), project),
    el("div", { class: "field" }, el("label", {}, "Nome do token"), name),
    el("div", { class: "field" }, el("label", {}, "Ambientes permitidos"), environments),
    el(
      "div",
      { class: "row" },
      el("label", { class: "field-inline" }, canList, "Listar nomes de chaves"),
      el("label", { class: "field-inline" }, canInject, "Executar com injeção"),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Comandos permitidos (um por linha, comparados palavra por palavra)"),
      commands,
    ),
    el("label", { class: "field-inline" }, anyCommand, "Permitir qualquer comando (não recomendado)"),
    el("p", { class: "note" }, "Com \"qualquer comando\", o token pode executar qualquer argv — inclusive programas que imprimem o ambiente. A redação é a última linha de defesa, não a única."),
  );
  openModal({
    title: "Novo token de agente",
    body,
    submitLabel: "Criar token",
    onSubmit: async () => {
      const envs = environments.value
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
      if (!envs.length) {
        toast("Informe ao menos um ambiente", "error");
        return false;
      }
      if (!canList.checked && !canInject.checked) {
        toast("O token precisa de ao menos uma permissão", "error");
        return false;
      }
      const allowed = commands.value
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean);
      if (canInject.checked && !allowed.length && !anyCommand.checked) {
        toast("Informe ao menos um comando ou marque \"qualquer comando\"", "error");
        return false;
      }
      if (anyCommand.checked && allowed.length) {
        toast("Escolha uma lista de comandos ou \"qualquer comando\", não os dois", "error");
        return false;
      }
      const result = await api("/v1/tokens", {
        method: "POST",
        body: {
          name: name.value.trim(),
          project_id: project.value,
          environments: envs,
          can_list: canList.checked,
          can_inject: canInject.checked,
          allowed_commands: allowed,
          any_command: anyCommand.checked,
        },
      });
      setTimeout(() => showTokenCreated(result), 120);
      await renderTokens();
      return true;
    },
  });
}

function openRevokeToken(token) {
  openModal({
    title: "Revogar token",
    danger: true,
    submitLabel: "Revogar",
    body: el("p", {}, `O token ${token.name} deixa de funcionar imediatamente. Execuções em andamento são encerradas.`),
    onSubmit: async () => {
      await api(`/v1/tokens/${token.id}`, { method: "DELETE" });
      toast("Token revogado");
      await renderTokens();
      return true;
    },
  });
}

function showTokenCreated(result) {
  const token = result.token;
  const code = el("div", { class: "code-block" }, token);
  const copy = el("button", { class: "btn small", type: "button" }, "Copiar token");
  copy.addEventListener("click", () => copyText(token));
  openModal({
    title: "Token criado — copie agora",
    body: el(
      "div",
      { class: "stack" },
      el("p", { class: "note" }, "Este valor aparece uma única vez. Se perder, revogue e crie outro."),
      code,
      el("div", { class: "row" }, copy),
      el("p", { class: "muted" }, "No ambiente do agente:"),
      el("div", { class: "code-block" }, `export ENVVAULT_TOKEN=${token}`),
      el(
        "p",
        { class: "muted" },
        `Escopo: ${result.item.project.slug} · ${result.item.environments.join(", ")}. Sem acesso a reveal/export.`,
      ),
    ),
    submitLabel: "Já copiei",
    hideCancel: true,
  });
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------
async function renderAudit() {
  setHeader("Auditoria", "Registro encadeado por hash: cada evento sela o anterior.", [
    { label: "Verificar integridade", onClick: async () => {
        try {
          const result = await api("/v1/audit/verify");
          if (result.valid) toast("Cadeia íntegra.");
          else toast(`Cadeia quebrada no id ${result.first_bad_id}`, "error");
        } catch (error) {
          toast(error.message, "error");
        }
      } },
    { label: "Atualizar", onClick: renderAudit },
  ]);
  if (!state.projects.length) await loadProjects();
  const filter = state.auditFilter;
  const project = el(
    "select",
    {},
    el("option", { value: "" }, "todos os projetos"),
    ...state.projects.map((item) => el("option", { value: item.slug }, item.slug)),
  );
  project.value = filter.project;
  const action = el("input", { value: filter.action, placeholder: "ação, ex.: secret." });
  const limit = el("input", { type: "number", min: "1", max: "500", value: String(filter.limit), style: "width:110px" });
  const apply = el("button", { class: "btn", type: "button" }, "Filtrar");
  apply.addEventListener("click", () => {
    state.auditFilter = { project: project.value, action: action.value.trim(), limit: Number(limit.value) || 100 };
    renderAudit();
  });
  const params = new URLSearchParams({ limit: String(filter.limit) });
  if (filter.project) params.set("project_slug", filter.project);
  if (filter.action) params.set("action", filter.action);
  const data = await api(`/v1/audit?${params.toString()}`);
  const rows = data.items.map((entry) => [
    fmtDate(entry.ts),
    `${entry.actor_type}:${entry.actor_name}`,
    entry.action,
    `${entry.project_slug || "—"}${entry.environment ? ` / ${entry.environment}` : ""}`,
    entry.key_names.join(", "),
    entry.command || "—",
    badge(entry.result, entry.result === "ok" ? "ok" : "err"),
  ]);
  const content = data.items.length
    ? table(["quando", "ator", "ação", "projeto", "chaves", "comando", "resultado"], rows, {
        onRowClick: (tr) => {
          const index = Array.from(tr.parentNode.children).indexOf(tr);
          openAuditDetail(data.items[index]);
        },
      })
    : el("p", { class: "muted" }, "Nenhum evento para este filtro.");
  view().replaceChildren(
    el("div", { class: "card row" }, project, action, limit, apply, el("div", { class: "spacer" }), el("span", { class: "muted" }, `${data.total} eventos`)),
    content,
  );
}

function openAuditDetail(entry) {
  openModal({
    title: `Evento #${entry.id}`,
    body: el("pre", { class: "code-block" }, JSON.stringify(entry, null, 2)),
    submitLabel: "Fechar",
    hideCancel: true,
  });
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------
async function renderSettings() {
  setHeader("Configurações", "Tempo de bloqueio, passphrase e informações da instância.", [
    { label: "Bloquear agora", danger: true, onClick: async () => {
        try {
          await api("/v1/auth/lock", { method: "POST" });
          showLogin("Cofre bloqueado.");
        } catch (error) {
          toast(error.message, "error");
        }
      } },
  ]);
  const data = await api("/v1/settings");
  const timeout = el("input", { type: "number", min: "1", max: "1440", value: String(data.lock_timeout_minutes), style: "max-width:140px" });
  const saveTimeout = el("button", { class: "btn primary", type: "button" }, "Salvar");
  saveTimeout.addEventListener("click", async () => {
    try {
      await api("/v1/settings", { method: "PUT", body: { lock_timeout_minutes: Number(timeout.value) } });
      toast("Timeout atualizado");
      await renderSettings();
    } catch (error) {
      toast(error.message, "error");
    }
  });

  const current = el("input", { type: "password", autocomplete: "current-password" });
  const next = el("input", { type: "password", autocomplete: "new-password" });
  const confirm = el("input", { type: "password", autocomplete: "new-password" });
  const change = el("button", { class: "btn primary", type: "button" }, "Trocar passphrase");
  change.addEventListener("click", async () => {
    if (next.value !== confirm.value) {
      toast("A confirmação não confere", "error");
      return;
    }
    if (next.value.length < 10) {
      toast("Use pelo menos 10 caracteres", "error");
      return;
    }
    change.disabled = true;
    try {
      await api("/v1/auth/passphrase", {
        method: "POST",
        body: { current: current.value, new: next.value },
      });
      current.value = next.value = confirm.value = "";
      toast("Passphrase alterada");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      change.disabled = false;
    }
  });

  view().replaceChildren(
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1fr 1fr" },
      section("Bloqueio por inatividade", [
        el("div", { class: "field" }, el("label", {}, "Minutos até bloquear"), timeout),
        el("div", { class: "row" }, saveTimeout),
        el("p", { class: "muted" }, "Ao bloquear, a chave sai da memória, sessões caem e processos em execução são encerrados."),
      ]),
      section("Trocar passphrase", [
        el("div", { class: "field" }, el("label", {}, "Passphrase atual"), current),
        el("div", { class: "field" }, el("label", {}, "Nova passphrase"), next),
        el("div", { class: "field" }, el("label", {}, "Confirmar nova"), confirm),
        el("div", { class: "row" }, change),
        el("p", { class: "muted" }, "A chave de dados é re-embrulhada; os segredos não são re-criptografados."),
      ]),
    ),
    section("Instância", [
      el(
        "dl",
        { class: "kv" },
        el("dt", {}, "Versão"),
        el("dd", {}, data.version),
        el("dt", {}, "Home"),
        el("dd", {}, data.home),
        el("dt", {}, "Banco"),
        el("dd", {}, data.database),
        el("dt", {}, "Endereço"),
        el("dd", {}, `${data.host}:${data.port}`),
        el("dt", {}, "Estado"),
        el("dd", {}, data.status.unlocked ? "desbloqueado" : "bloqueado"),
      ),
      el("p", { class: "muted" }, "API local: /api/docs · dados criptografados com AES-256-GCM e chave derivada por Argon2id."),
    ]),
  );
}

bootstrap();
