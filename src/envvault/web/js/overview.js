import { api } from "./api.js";
import { badge, el, fmtDate, metricCard, section, setHeader, table, view } from "./dom.js";
import { openProjectDialog } from "./projects.js";

export async function renderOverview() {
  setHeader("Overview", "What is in the vault and what happened recently.", [
    { label: "Refresh", onClick: renderOverview },
    { label: "New project", primary: true, onClick: () => openProjectDialog() },
  ]);
  const data = await api("/v1/overview");
  const status = data.status;
  const cards = el(
    "div",
    { class: "grid" },
    metricCard("Projects", data.projects, "registered directories"),
    metricCard("Secrets", data.secrets, "encrypted values"),
    metricCard("Environments", data.environments, "dev, prod, staging…"),
    metricCard("Credentials", data.credentials, "external services"),
    metricCard("Active tokens", data.active_tokens, "agent access"),
  );
  const statusCard = el(
    "div",
    { class: "card stack" },
    el("div", { class: "row" }, el("h3", {}, "Vault status"), badge(status.unlocked ? "unlocked" : "locked", status.unlocked ? "ok" : "warn")),
    el(
      "dl",
      { class: "kv" },
      el("dt", {}, "Database"),
      el("dd", {}, data.paths.database),
      el("dt", {}, "Timeout"),
      el("dd", {}, `${status.lock_timeout_minutes} min of inactivity · maximum ${status.max_unlock_hours} h unlocked`),
      el("dt", {}, "Version"),
      el("dd", {}, data.version),
    ),
    el(
      "p",
      { class: "muted" },
      "Claude only receives the redacted output of commands. Values only leave the vault via reveal/export, always audited.",
    ),
  );
  const recent = data.recent_audit.length
    ? table(
        ["when", "actor", "action", "project", "result"],
        data.recent_audit.map((entry) => [
          fmtDate(entry.ts),
          `${entry.actor_type}:${entry.actor_name}`,
          entry.action,
          entry.project_slug || "—",
          badge(entry.result, entry.result === "ok" ? "ok" : "err"),
        ]),
      )
    : el("p", { class: "muted" }, "No events yet.");
  view().replaceChildren(
    cards,
    el(
      "div",
      { class: "grid", style: "grid-template-columns: 1.2fr 1fr;align-items:start" },
      statusCard,
      section("Recent activity", [recent]),
    ),
  );
}
