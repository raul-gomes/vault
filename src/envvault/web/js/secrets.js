import { api } from "./api.js";
import { askPassphrase, copyText, dialog, el, openModal, showIssues, toast } from "./dom.js";
import { refreshProject } from "./projects.js";
import { state } from "./state.js";

export function openSecretDialog(project, environment, secret = null) {
  const editing = Boolean(secret);
  const key = el("input", {
    value: secret?.key || "",
    disabled: editing,
    placeholder: "DATABASE_URL",
    autocomplete: "off",
  });
  const value = el("input", {
    type: "password",
    placeholder: editing ? "new value (the current one is not shown)" : "secret value",
    autocomplete: "new-password",
  });
  const reveal = el("button", { class: "btn small", type: "button" }, "Show");
  reveal.addEventListener("click", () => {
    const hidden = value.type === "password";
    value.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Hide" : "Show";
  });

  const length = el("input", { type: "number", min: "8", max: "256", value: "32", style: "width:90px" });
  const upper = el("input", { type: "checkbox", checked: true });
  const lower = el("input", { type: "checkbox", checked: true });
  const digits = el("input", { type: "checkbox", checked: true });
  const symbols = el("input", { type: "checkbox", checked: true });
  const entropy = el("span", { class: "muted" }, "");
  const generate = el("button", { class: "btn small", type: "button" }, "Generate password");
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
      reveal.textContent = "Hide";
      value.value = data.password;
      entropy.textContent = `~${data.entropy_bits} bits · ${data.alphabet_size} symbols`;
    } catch (error) {
      toast(error.message, "error");
    } finally {
      generate.disabled = false;
    }
  });

  const generator = el(
    "div",
    { class: "card stack", style: "padding:14px;background:var(--panel-2)" },
    el("div", { class: "row" }, el("strong", {}, "Built-in generator"), el("div", { class: "spacer" }), generate),
    el(
      "div",
      { class: "row" },
      el("label", { class: "field-inline" }, "Length", length),
      el("label", { class: "field-inline" }, upper, "A-Z"),
      el("label", { class: "field-inline" }, lower, "a-z"),
      el("label", { class: "field-inline" }, digits, "0-9"),
      el("label", { class: "field-inline" }, symbols, "symbols"),
      entropy,
    ),
  );

  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, "Key"), key),
    el(
      "div",
      { class: "field" },
      el("label", {}, editing ? "New value" : "Value"),
      el("div", { class: "row" }, value, reveal),
    ),
    editing ? null : generator,
    el("p", { class: "note info" }, "The value is encrypted before it touches SQLite. It only leaves the vault via reveal or export, both audited."),
  );

  openModal({
    title: `${editing ? "Edit" : "New"} secret · ${project.slug}/${environment}`,
    body,
    submitLabel: editing ? "Update" : "Save",
    onSubmit: async () => {
      if (!key.value.trim() || !value.value) {
        toast("Fill in key and value", "error");
        return false;
      }
      await api(`/v1/projects/${project.id}/secrets`, {
        method: "PUT",
        body: { environment, key: key.value.trim(), value: value.value },
      });
      toast(editing ? "Secret updated" : "Secret created");
      state.environment = environment;
      await refreshProject();
      return true;
    },
  });
}

export function openDeleteSecret(project, environment, secret) {
  openModal({
    title: "Delete secret",
    danger: true,
    submitLabel: "Delete",
    body: el("p", {}, `Remove ${secret.key} from ${project.slug}/${environment}? This cannot be undone.`),
    onSubmit: async () => {
      await api(
        `/v1/projects/${project.id}/secrets/${encodeURIComponent(secret.key)}?environment=${encodeURIComponent(environment)}`,
        { method: "DELETE" },
      );
      toast("Secret deleted");
      await refreshProject();
      return true;
    },
  });
}

export async function openRevealDialog(project, environment, secret) {
  const passphrase = await askPassphrase(
    `Reveal ${secret.key}`,
    "The passphrase is re-validated and the access is recorded in the audit log.",
  );
  if (!passphrase) return;
  try {
    const data = await api(`/v1/projects/${project.id}/secrets/${encodeURIComponent(secret.key)}/reveal`, {
      method: "POST",
      body: { environment, passphrase },
    });
    const code = el("div", { class: "code-block" }, data.value);
    const copy = el("button", { class: "btn small", type: "button" }, "Copy");
    copy.addEventListener("click", () => copyText(data.value));
    const timerLabel = el("span", { class: "muted" }, "hidden in 60s");
    const timer = setTimeout(() => {
      code.textContent = "•••••••• (value hidden)";
      copy.disabled = true;
      timerLabel.textContent = "value hidden";
    }, 60000);
    dialog().addEventListener("close", () => clearTimeout(timer), { once: true });
    openModal({
      title: `${secret.key} · ${environment}`,
      body: el(
        "div",
        { class: "stack" },
        el("p", { class: "note" }, "Do not paste this value into chats, issues or logs. If it shows up anywhere, rotate it."),
        code,
        el("div", { class: "row" }, copy, timerLabel),
      ),
      submitLabel: "Close",
      hideCancel: true,
    });
  } catch (error) {
    toast(error.message, "error");
  }
}

export function openImportDialog(project, environment) {
  const file = el("input", { type: "file", accept: ".env,.txt,text/plain" });
  const text = el("textarea", { rows: "8", placeholder: "or paste the .env content here" });
  const target = el("input", { value: environment });
  const replace = el("input", { type: "checkbox" });
  const body = el(
    "div",
    { class: "stack" },
    el("div", { class: "field" }, el("label", {}, ".env file"), file),
    el("div", { class: "field" }, el("label", {}, "Content"), text),
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1fr 1fr" },
      el("div", { class: "field" }, el("label", {}, "Target environment"), target),
      el("label", { class: "field-inline", style: "align-self:end;padding-bottom:9px" }, replace, "Overwrite existing keys"),
    ),
    el("p", { class: "note info" }, "The parser accepts comments, export, single/double quotes and never executes the content."),
  );
  openModal({
    title: `Import .env · ${project.slug}`,
    body,
    submitLabel: "Import",
    onSubmit: async () => {
      let content = text.value;
      if (file.files?.length) content = await file.files[0].text();
      if (!content.trim()) {
        toast("Select a file or paste the content", "error");
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
        `${result.created} created, ${result.updated} updated, ${result.skipped} skipped`,
      );
      state.environment = target.value.trim().toLowerCase();
      await refreshProject();
      if (result.issues.length) setTimeout(() => showIssues(result.issues), 150);
      return true;
    },
  });
}

export async function openExportDialog(project, environment) {
  const passphrase = await askPassphrase(
    `Export ${project.slug}/${environment}`,
    "A temporary .env will be generated. Prefer `envvault run` to avoid leaving values on disk.",
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
    toast("File exported. Delete it after use.");
  } catch (error) {
    toast(error.message, "error");
  }
}
