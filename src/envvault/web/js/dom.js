export const $id = (id) => document.getElementById(id);
export const view = () => $id("view");
export const dialog = () => $id("modal");

export function el(tag, attrs = {}, ...children) {
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

export function toast(message, kind = "ok") {
  const node = $id("toast");
  node.textContent = message;
  node.className = `toast ${kind === "error" ? "error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.add("hidden"), 4200);
}

export function fmtDate(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("en", { dateStyle: "short", timeStyle: "short" });
}

export function badge(text, kind = "") {
  return el("span", { class: `badge ${kind}` }, text);
}

export function setHeader(title, subtitle, actions = []) {
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

export function setActiveNav(name) {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === name);
  });
}

export function loading() {
  view().replaceChildren(el("p", { class: "muted" }, "Loading…"));
}

export function section(title, children, actions = []) {
  const head = el(
    "div",
    { class: "section-title" },
    el("h3", {}, title),
    actions.length ? el("div", { class: "row" }, ...actions) : el("span"),
  );
  return el("div", { class: "card stack" }, head, ...children);
}

export function metricCard(label, value, hint) {
  return el(
    "div",
    { class: "card" },
    el("div", { class: "card-title" }, label),
    el("div", { class: "metric" }, String(value)),
    hint ? el("p", { class: "muted" }, hint) : null,
  );
}

export function table(headers, rows, options = {}) {
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

export function emptyState(title, description, actionLabel, action) {
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

export function openModal({ title, body, submitLabel = "Save", danger = false, hideCancel = false, onSubmit }) {
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

export function askPassphrase(title, description) {
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
      submitLabel: "Confirm",
      onSubmit: () => {
        if (!input.value) {
          toast("Enter the passphrase", "error");
          return false;
        }
        settled = true;
        resolve(input.value);
        return true;
      },
    });
  });
}

export function showIssues(issues) {
  if (!issues.length) return;
  const list = el(
    "div",
    { class: "stack" },
    ...issues.map((issue) =>
      el(
        "div",
        { class: issue.level === "warning" ? "note" : "note" },
        `Line ${issue.line}: ${issue.message}`,
      ),
    ),
  );
  openModal({
    title: ".env warnings",
    body: list,
    submitLabel: "Got it",
    hideCancel: true,
  });
}

export function promptText(title, description, placeholder = "") {
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
      submitLabel: "Confirm",
      onSubmit: () => {
        if (!input.value.trim()) return false;
        settled = true;
        resolve(input.value.trim());
        return true;
      },
    });
  });
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to the clipboard.");
  } catch {
    toast("Could not copy", "error");
  }
}
