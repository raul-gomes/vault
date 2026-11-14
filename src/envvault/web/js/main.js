/* EnvVault dashboard entry: plain ES modules, no external dependencies. */

import { api } from "./api.js";
import { renderAudit } from "./audit.js";
import { renderCredentials } from "./credentials.js";
import { $id, dialog, el, loading, setActiveNav, toast, view } from "./dom.js";
import { renderOverview } from "./overview.js";
import { renderProject, renderProjects } from "./projects.js";
import { renderSettings } from "./settings.js";
import { showLogin, showShell } from "./shell.js";
import { state } from "./state.js";
import { renderTokens } from "./tokens.js";

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
    if (!response.ok) throw new Error(payload.detail || "Failed to unlock");
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
    showLogin("Vault locked.");
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
          ? "Vault not initialized yet. Run `envvault init` in the terminal."
          : "",
      );
    }
  } catch {
    showLogin("Daemon unavailable. Run `envvault serve` or `envvault init`.");
  }
}

export async function route() {
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

bootstrap();
