import { api } from "./api.js";
import { el, section, setHeader, toast, view } from "./dom.js";
import { showLogin } from "./shell.js";

export async function renderSettings() {
  setHeader("Settings", "Lock timeout, passphrase and instance information.", [
    { label: "Lock now", danger: true, onClick: async () => {
        try {
          await api("/v1/auth/lock", { method: "POST" });
          showLogin("Vault locked.");
        } catch (error) {
          toast(error.message, "error");
        }
      } },
  ]);
  const data = await api("/v1/settings");
  const timeout = el("input", { type: "number", min: "1", max: "1440", value: String(data.lock_timeout_minutes), style: "max-width:140px" });
  const maxUnlock = el("input", { type: "number", min: "1", max: "168", value: String(data.max_unlock_hours), style: "max-width:140px" });
  const saveTimeout = el("button", { class: "btn primary", type: "button" }, "Save");
  saveTimeout.addEventListener("click", async () => {
    try {
      await api("/v1/settings", {
        method: "PUT",
        body: { lock_timeout_minutes: Number(timeout.value), max_unlock_hours: Number(maxUnlock.value) },
      });
      toast("Timeout updated");
      await renderSettings();
    } catch (error) {
      toast(error.message, "error");
    }
  });

  const current = el("input", { type: "password", autocomplete: "current-password" });
  const next = el("input", { type: "password", autocomplete: "new-password" });
  const confirm = el("input", { type: "password", autocomplete: "new-password" });
  const change = el("button", { class: "btn primary", type: "button" }, "Change passphrase");
  change.addEventListener("click", async () => {
    if (next.value !== confirm.value) {
      toast("The confirmation does not match", "error");
      return;
    }
    if (next.value.length < 10) {
      toast("Use at least 10 characters", "error");
      return;
    }
    change.disabled = true;
    try {
      await api("/v1/auth/passphrase", {
        method: "POST",
        body: { current: current.value, new: next.value },
      });
      current.value = next.value = confirm.value = "";
      toast("Passphrase changed");
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
      section("Automatic lock", [
        el("div", { class: "field" }, el("label", {}, "Minutes until lock"), timeout),
        el("div", { class: "field" }, el("label", {}, "Maximum hours unlocked (even while in use)"), maxUnlock),
        el("div", { class: "row" }, saveTimeout),
        el("p", { class: "muted" }, "On lock, the key leaves memory, sessions are dropped and running processes are terminated."),
      ]),
      section("Change passphrase", [
        el("div", { class: "field" }, el("label", {}, "Current passphrase"), current),
        el("div", { class: "field" }, el("label", {}, "New passphrase"), next),
        el("div", { class: "field" }, el("label", {}, "Confirm new"), confirm),
        el("div", { class: "row" }, change),
        el("p", { class: "muted" }, "The data key is re-wrapped; secrets are not re-encrypted."),
      ]),
    ),
    section("Instance", [
      el(
        "dl",
        { class: "kv" },
        el("dt", {}, "Version"),
        el("dd", {}, data.version),
        el("dt", {}, "Home"),
        el("dd", {}, data.home),
        el("dt", {}, "Database"),
        el("dd", {}, data.database),
        el("dt", {}, "Address"),
        el("dd", {}, `${data.host}:${data.port}`),
        el("dt", {}, "Status"),
        el("dd", {}, data.status.unlocked ? "unlocked" : "locked"),
      ),
      el("p", { class: "muted" }, "Local API: /api/docs · data encrypted with AES-256-GCM and a key derived with Argon2id."),
    ]),
  );
}
