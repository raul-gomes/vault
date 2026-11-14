import { api } from "./api.js";
import { badge, el, fmtDate, openModal, setHeader, table, toast, view } from "./dom.js";
import { loadProjects } from "./projects.js";
import { state } from "./state.js";

export async function renderAudit() {
  setHeader("Audit log", "Hash-chained log: each event seals the previous one.", [
    { label: "Verify integrity", onClick: async () => {
        try {
          const result = await api("/v1/audit/verify");
          if (result.valid) toast("Chain intact.");
          else toast(`Chain broken at id ${result.first_bad_id}`, "error");
        } catch (error) {
          toast(error.message, "error");
        }
      } },
    { label: "Refresh", onClick: renderAudit },
  ]);
  if (!state.projects.length) await loadProjects();
  const filter = state.auditFilter;
  const project = el(
    "select",
    {},
    el("option", { value: "" }, "all projects"),
    ...state.projects.map((item) => el("option", { value: item.slug }, item.slug)),
  );
  project.value = filter.project;
  const action = el("input", { value: filter.action, placeholder: "action, e.g. secret." });
  const limit = el("input", { type: "number", min: "1", max: "500", value: String(filter.limit), style: "width:110px" });
  const apply = el("button", { class: "btn", type: "button" }, "Filter");
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
    ? table(["when", "actor", "action", "project", "keys", "command", "result"], rows, {
        onRowClick: (tr) => {
          const index = Array.from(tr.parentNode.children).indexOf(tr);
          openAuditDetail(data.items[index]);
        },
      })
    : el("p", { class: "muted" }, "No events for this filter.");
  view().replaceChildren(
    el("div", { class: "card row" }, project, action, limit, apply, el("div", { class: "spacer" }), el("span", { class: "muted" }, `${data.total} events`)),
    content,
  );
}

export function openAuditDetail(entry) {
  openModal({
    title: `Event #${entry.id}`,
    body: el("pre", { class: "code-block" }, JSON.stringify(entry, null, 2)),
    submitLabel: "Close",
    hideCancel: true,
  });
}
