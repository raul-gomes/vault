import { view } from "./dom.js";

export const state = {
  csrf: null,
  version: "",
  view: "overview",
  projects: [],
  project: null,
  environment: null,
  secrets: [],
  credentials: [],
  projectCredentials: [],
  credentialFilter: { query: "", category: "", project: "" },
  auditFilter: { project: "", action: "", limit: 100 },
  execAbort: null,
};
