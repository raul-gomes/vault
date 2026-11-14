import { credentialCategoryLabel, openCredentialDialog, openDeleteCredential, openRevealCredential } from "./credentials.js";
import { el, fmtDate, section, table } from "./dom.js";
import { state } from "./state.js";

export function buildProjectCredentials(project) {
  const own = state.projectCredentials.filter((item) => item.scope === "project");
  const globals = state.projectCredentials.filter((item) => item.scope === "global");

  const ownRows = own.map((credential) => [
    el("span", { class: "mono" }, credential.name),
    el("span", { class: "tag" }, credentialCategoryLabel(credential.category)),
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

  const ownContent = own.length
    ? table(["name", "category", "version", "updated", ""], ownRows)
    : el(
        "p",
        { class: "muted" },
        "No credentials specific to this project. The global ones below are also available here.",
      );

  const globalRows = globals.map((credential) => [
    el("span", { class: "mono" }, credential.name),
    el("span", { class: "tag" }, credentialCategoryLabel(credential.category)),
    el("span", { class: "tag" }, `v${credential.version}`),
    el(
      "button",
      { class: "btn small", type: "button", onclick: () => openRevealCredential(credential) },
      "Reveal",
    ),
  ]);

  const children = [
    el(
      "div",
      { class: "row" },
      el(
        "button",
        {
          class: "btn primary small",
          type: "button",
          onclick: () => openCredentialDialog(null, project),
        },
        "New credential for this project",
      ),
      el(
        "button",
        {
          class: "btn small",
          type: "button",
          onclick: () => {
            state.credentialFilter = { query: "", category: "", project: project.id };
            location.hash = "#/credentials";
          },
        },
        "Manage all",
      ),
    ),
    ownContent,
  ];

  if (globals.length) {
    children.push(
      el("p", { class: "muted" }, "Global credentials available in this project"),
      table(["name", "category", "version", ""], globalRows),
    );
  }

  return section("Project credentials", children);
}
