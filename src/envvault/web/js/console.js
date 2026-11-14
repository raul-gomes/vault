import { ApiError } from "./api.js";
import { el, toast } from "./dom.js";
import { showLogin } from "./shell.js";
import { state } from "./state.js";

export function buildConsole(project, env) {
  const command = el("input", { id: "exec-command", placeholder: "npm run dev", autocomplete: "off" });
  const cwd = el("input", { id: "exec-cwd", placeholder: project.path, autocomplete: "off" });
  const output = el("pre", { id: "exec-output", class: "output" });
  const runButton = el("button", { class: "btn primary", type: "button" }, "Run");
  const stopButton = el("button", { class: "btn danger", type: "button", disabled: true }, "Stop");
  const note = el("p", { class: "muted" }, "Output goes through the secret redactor. Commands are audited.");

  runButton.addEventListener("click", async () => {
    const argv = splitCommand(command.value.trim());
    if (!argv.length) {
      toast("Enter a command", "error");
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
        showLogin("Session expired. Sign in again.");
        return;
      }
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new ApiError(payload.detail || "Failed to run", response.status);
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
      if (error.name === "AbortError") toast("Run canceled.");
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
      el("div", { class: "field" }, el("label", {}, "Command (argv, no shell)"), command),
      el("div", { class: "field" }, el("label", {}, "Directory (inside the project)"), cwd),
    ),
    el("div", { class: "row" }, runButton, stopButton, el("div", { class: "spacer" }), note),
    output,
  );
}

export function handleSseFrame(frame, output) {
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
      toast(ok ? "Command finished (code 0)." : `Command exited with code ${event.code}.`, ok ? "ok" : "error");
    }
  }
}

export function splitCommand(line) {
  const parts = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = pattern.exec(line))) {
    parts.push(match[1] ?? match[2] ?? match[3]);
  }
  return parts;
}
