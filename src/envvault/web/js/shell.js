import { $id } from "./dom.js";
import { route } from "./main.js";
import { state } from "./state.js";

export function showLogin(message = "") {
  state.csrf = null;
  state.execAbort?.abort();
  $id("shell").classList.add("hidden");
  $id("login-view").classList.remove("hidden");
  $id("login-error").textContent = message;
  $id("passphrase").value = "";
  setTimeout(() => $id("passphrase").focus(), 40);
}

export function showShell() {
  $id("login-view").classList.add("hidden");
  $id("shell").classList.remove("hidden");
  $id("sidebar-version").textContent = `v${state.version}`;
  route();
}
