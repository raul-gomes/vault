import { api } from "./api.js";
import { askPassphrase, badge, copyText, dialog, el, emptyState, fmtDate, openModal, setHeader, table, toast, view } from "./dom.js";
import { loadProjects, refreshProject } from "./projects.js";
import { state } from "./state.js";

export const CREDENTIAL_CATEGORIES = [
  ["hosting", "Hosting"],
  ["dns", "DNS / domains"],
  ["email", "Email"],
  ["smtp", "SMTP / sending"],
  ["api", "API / token"],
  ["database", "Database"],
  ["other", "Other"],
];

export function credentialCategoryLabel(value) {
  const found = CREDENTIAL_CATEGORIES.find(([slug]) => slug === value);
  return found ? found[1] : value;
}

export async function refreshCredentialViews() {
  if (state.project && location.hash.startsWith("#/projects/")) {
    await refreshProject();
  } else {
    await renderCredentials();
  }
}

export async function renderCredentials() {
  setHeader(
    "Credentials",
    "Logins for external services, global or per project (client). Sensitive fields only leave the vault via audited reveal.",
    [
      { label: "Refresh", onClick: renderCredentials },
      { label: "New credential", primary: true, onClick: () => openCredentialDialog() },
    ],
  );
  if (!state.projects.length) await loadProjects();
  const filter = state.credentialFilter;
  const query = el("input", {
    value: filter.query,
    placeholder: "search by name or category",
    autocomplete: "off",
  });
  const category = el(
    "select",
    {},
    el("option", { value: "" }, "all categories"),
    ...CREDENTIAL_CATEGORIES.map(([slug, label]) => el("option", { value: slug }, label)),
  );
  category.value = filter.category;
  const project = el(
    "select",
    {},
    el("option", { value: "" }, "all scopes"),
    el("option", { value: "__global__" }, "global only"),
    ...state.projects.map((item) =>
      el("option", { value: item.id }, `project: ${item.slug}`),
    ),
  );
  project.value = filter.project;
  const apply = el("button", { class: "btn", type: "button" }, "Filter");
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
        "Reveal",
      ),
      el(
        "button",
        { class: "btn small", type: "button", onclick: () => openCredentialDialog(credential) },
        "Edit",
      ),
      el(
        "button",
        { class: "btn small danger", type: "button", onclick: () => openDeleteCredential(credential) },
        "Delete",
      ),
    ),
  ]);

  const content = data.items.length
    ? table(["name", "category", "scope", "version", "updated", ""], rows)
    : emptyState(
        "No credentials yet",
        "Store logins for Hostinger, Cloudflare, Gmail, SMTP and other services. Use the global scope for your own and a project for each client.",
        "Add credential",
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
      el("span", { class: "muted" }, `${data.total} credentials`),
    ),
    content,
    el(
      "p",
      { class: "note info" },
      "Name, category and scope are visible for search. Username, password, URL and notes are encrypted together and never appear in listings. Agent tokens have no access to this area.",
    ),
  );
}

export async function openCredentialDialog(credential = null, defaultProject = null) {
  const editing = Boolean(credential);
  if (!state.projects.length) await loadProjects();
  let current = { username: "", password: "", url: "", notes: "" };
  if (editing) {
    const passphrase = await askPassphrase(
      `Edit ${credential.name}`,
      "To edit the encrypted fields the passphrase is re-validated. The access is recorded in the audit log.",
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
    el("option", { value: "" }, "Global (all projects)"),
    ...state.projects.map((item) =>
      el("option", { value: item.id }, `Project: ${item.slug} — ${item.name}`),
    ),
  );
  project.value = credential?.project?.id || defaultProject?.id || "";
  const username = el("input", {
    value: current.username || "",
    placeholder: "user@example.com",
    autocomplete: "off",
  });
  const password = el("input", {
    type: "password",
    value: current.password || "",
    placeholder: "password or token",
    autocomplete: "new-password",
  });
  const url = el("input", { value: current.url || "", placeholder: "https://dashboard.service.com" });
  const notes = el("textarea", { rows: "4", placeholder: "notes, token scope, etc." });
  notes.value = current.notes || "";

  const reveal = el("button", { class: "btn small", type: "button" }, "Show");
  reveal.addEventListener("click", () => {
    const hidden = password.type === "password";
    password.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Hide" : "Show";
  });

  const length = el("input", {
    type: "number",
    min: "8",
    max: "256",
    value: "32",
    style: "width:90px",
  });
  const entropy = el("span", { class: "muted" }, "");
  const generate = el("button", { class: "btn small", type: "button" }, "Generate password");
  generate.addEventListener("click", async () => {
    generate.disabled = true;
    try {
      const data = await api("/v1/generate", {
        method: "POST",
        body: { length: Number(length.value) },
      });
      password.type = "text";
      reveal.textContent = "Hide";
      password.value = data.password;
      entropy.textContent = `~${data.entropy_bits} bits · ${data.alphabet_size} symbols`;
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
      el("div", { class: "field" }, el("label", {}, "Name"), name),
      el("div", { class: "field" }, el("label", {}, "Category"), category),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Scope"),
      project,
      el(
        "p",
        { class: "muted" },
        "Global = shared by all projects. Project = specific to one client.",
      ),
    ),
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Username / email"), username),
      el("div", { class: "field" }, el("label", {}, "Dashboard URL"), url),
    ),
    el(
      "div",
      { class: "field" },
      el("label", {}, "Password / token"),
      el("div", { class: "row" }, password, reveal),
    ),
    el(
      "div",
      { class: "card stack", style: "padding:12px;background:var(--panel-2)" },
      el(
        "div",
        { class: "row" },
        el("strong", {}, "Built-in generator"),
        el("label", { class: "field-inline" }, "Length", length),
        generate,
        entropy,
      ),
    ),
    el("div", { class: "field" }, el("label", {}, "Notes"), notes),
    el(
      "p",
      { class: "note info" },
      "Username, password, URL and notes are encrypted in a single AES-256-GCM payload. Only name and category are visible.",
    ),
  );

  openModal({
    title: editing ? `Edit credential · ${credential.name}` : "New credential",
    body,
    submitLabel: editing ? "Save" : "Create",
    onSubmit: async () => {
      if (!name.value.trim()) {
        toast("Enter a name", "error");
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
        toast("Credential updated");
      } else {
        await api("/v1/credentials", { method: "POST", body: payload });
        toast("Credential created");
      }
      await refreshCredentialViews();
      return true;
    },
  });
}

export async function openRevealCredential(credential) {
  const passphrase = await askPassphrase(
    `Reveal ${credential.name}`,
    "The passphrase is re-validated and the access is recorded in the audit log.",
  );
  if (!passphrase) return;
  try {
    const data = await api(`/v1/credentials/${credential.id}/reveal`, {
      method: "POST",
      body: { passphrase },
    });
    const password = el("div", { class: "code-block" }, data.password || "(no saved password)");
    const copy = el("button", { class: "btn small", type: "button" }, "Copy password");
    copy.disabled = !data.password;
    copy.addEventListener("click", () => copyText(data.password));
    const timerLabel = el("span", { class: "muted" }, "hidden in 60s");
    const timer = setTimeout(() => {
      password.textContent = "•••••••• (password hidden)";
      copy.disabled = true;
      timerLabel.textContent = "password hidden";
    }, 60000);
    dialog().addEventListener("close", () => clearTimeout(timer), { once: true });

    const details = el(
      "dl",
      { class: "kv" },
      el("dt", {}, "Scope"),
      el("dd", {}, data.project ? `project ${data.project.slug}` : "global"),
      el("dt", {}, "Category"),
      el("dd", {}, credentialCategoryLabel(data.category)),
      el("dt", {}, "Username"),
      el("dd", {}, data.username || "—"),
      el("dt", {}, "URL"),
      el("dd", {}, data.url || "—"),
      el("dt", {}, "Notes"),
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
          "Do not paste these values into chats, issues or logs. If they show up anywhere, rotate them.",
        ),
        details,
        el("div", { class: "field" }, el("label", {}, "Password / token"), password),
        el("div", { class: "row" }, copy, timerLabel),
      ),
      submitLabel: "Close",
      hideCancel: true,
    });
  } catch (error) {
    toast(error.message, "error");
  }
}

export function openDeleteCredential(credential) {
  openModal({
    title: "Delete credential",
    danger: true,
    submitLabel: "Delete",
    body: el(
      "p",
      {},
      `Remove ${credential.name} (${credentialCategoryLabel(credential.category)})? This cannot be undone.`,
    ),
    onSubmit: async () => {
      await api(`/v1/credentials/${credential.id}`, { method: "DELETE" });
      toast("Credential deleted");
      await refreshCredentialViews();
      return true;
    },
  });
}
