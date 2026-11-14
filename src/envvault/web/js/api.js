import { showLogin } from "./shell.js";
import { state } from "./state.js";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function api(path, options = {}) {
  const { method = "GET", body, raw = false } = options;
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (state.csrf && method !== "GET" && method !== "HEAD") {
    headers["x-csrf-token"] = state.csrf;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 || response.status === 423) {
    showLogin(
      response.status === 423
        ? "The vault was locked due to inactivity. Sign in again."
        : "Session expired. Sign in again.",
    );
    throw new ApiError("not authenticated", response.status);
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = await response.json();
      if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
      } else if (payload.detail) {
        detail = payload.detail;
      }
    } catch {
      /* keep statusText */
    }
    throw new ApiError(detail, response.status);
  }
  if (raw) return response;
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}
