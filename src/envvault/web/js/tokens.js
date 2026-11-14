import { api } from "./api.js";
import { badge, copyText, el, emptyState, fmtDate, openModal, setHeader, table, toast, view } from "./dom.js";
import { loadProjects } from "./projects.js";
import { state } from "./state.js";

export async function renderTokens() {
  setHeader("Tokens", "Agent credentials with restricted scope. They can never reveal values.", [
    { label: "Refresh", onClick: renderTokens },
    { label: "New token", primary: true, onClick: () => openTokenDialog() },
  ]);
  const [tokens, projects] = await Promise.all([api("/v1/tokens"), loadProjects()]);
  const items = tokens.items;
  const rows = items.map((token) => [
    el("span", { class: "mono" }, token.name),
    token.project.slug,
    el("div", { class: "row" }, ...token.environments.map((env) => el("span", { class: "tag" }, env))),
    [
      token.can_list ? "list" : null,
      token.can_inject ? "run" : null,
    ].filter(Boolean).join(" · "),
    token.any_command
      ? el("span", { class: "badge warn" }, "any command")
      : token.allowed_commands.length
        ? el("span", { class: "mono muted" }, token.allowed_commands.join(", "))
        : el("span", { class: "badge err" }, token.can_inject ? "recreate (no commands)" : "—"),
    fmtDate(token.last_used_at),
    badge(token.active ? "active" : "revoked", token.active ? "ok" : "err"),
    token.active
      ? el(
          "button",
          {
            class: "btn small danger",
            type: "button",
            onclick: () => openRevokeToken(token),
          },
          "Revoke",
        )
      : el("span", { class: "muted" }, "—"),
  ]);
  const content = items.length
    ? table(
        ["name", "project", "environments", "permissions", "commands", "last used", "status", ""],
        rows,
      )
    : emptyState(
        "No tokens created",
        "Create a token so Claude can run commands with secrets without receiving the values.",
        "Create token",
        () => openTokenDialog(),
      );
  view().replaceChildren(
    content,
    el(
      "p",
      { class: "note info" },
      "The token gives no access to the dashboard or to reveal/export. Prefer restricting environments and command prefixes; an unrestricted token can run any argv.",
    ),
  );
}

export function openTokenDialog() {
  const projects = state.projects.length ? state.projects : [];
  if (!projects.length) {
    toast("Register a project before creating tokens", "error");
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
    el("div", { class: "field" }, el("label", {}, "Project"), project),
    el("div", { class: "field" }, el("label", {}, "Token name"), name),
    el("div", { class: "field" }, el("label", {}, "Allowed environments"), environments),
    el(
      "div",
      { class: "row" },
      el("label", { class: "field-inline" }, canList, "List key names"),
      el("label", { class: "field-inline" }, canInject, "Run with injection"),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Allowed commands (one per line, compared word by word)"),
      commands,
    ),
    el("label", { class: "field-inline" }, anyCommand, "Allow any command (not recommended)"),
    el("p", { class: "note" }, "With \"any command\", the token can run any argv — including programs that print the environment. Redaction is the last line of defense, not the only one."),
  );
  openModal({
    title: "New agent token",
    body,
    submitLabel: "Create token",
    onSubmit: async () => {
      const envs = environments.value
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
      if (!envs.length) {
        toast("Enter at least one environment", "error");
        return false;
      }
      if (!canList.checked && !canInject.checked) {
        toast("The token needs at least one permission", "error");
        return false;
      }
      const allowed = commands.value
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean);
      if (canInject.checked && !allowed.length && !anyCommand.checked) {
        toast("Enter at least one command or check \"any command\"", "error");
        return false;
      }
      if (anyCommand.checked && allowed.length) {
        toast("Choose a command list or \"any command\", not both", "error");
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

export function openRevokeToken(token) {
  openModal({
    title: "Revoke token",
    danger: true,
    submitLabel: "Revoke",
    body: el("p", {}, `Token ${token.name} stops working immediately. Running executions are terminated.`),
    onSubmit: async () => {
      await api(`/v1/tokens/${token.id}`, { method: "DELETE" });
      toast("Token revoked");
      await renderTokens();
      return true;
    },
  });
}

export function showTokenCreated(result) {
  const token = result.token;
  const code = el("div", { class: "code-block" }, token);
  const copy = el("button", { class: "btn small", type: "button" }, "Copy token");
  copy.addEventListener("click", () => copyText(token));
  openModal({
    title: "Token created — copy it now",
    body: el(
      "div",
      { class: "stack" },
      el("p", { class: "note" }, "This value is shown only once. If you lose it, revoke it and create another."),
      code,
      el("div", { class: "row" }, copy),
      el("p", { class: "muted" }, "In the agent environment:"),
      el("div", { class: "code-block" }, `export ENVVAULT_TOKEN=${token}`),
      el(
        "p",
        { class: "muted" },
        `Scope: ${result.item.project.slug} · ${result.item.environments.join(", ")}. No access to reveal/export.`,
      ),
    ),
    submitLabel: "I have copied it",
    hideCancel: true,
  });
}
