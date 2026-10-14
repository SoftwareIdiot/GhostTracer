const STORAGE_KEY = "ghosttrace.extensionId";

export function rememberedExtensionId() {
  return new URLSearchParams(location.search).get("extensionId") || localStorage.getItem(STORAGE_KEY) || "";
}

export function rememberExtensionId(id) {
  const clean = id.trim();
  localStorage.setItem(STORAGE_KEY, clean);
  return clean;
}

export function extensionRequest(extensionId, type, extra = {}) {
  return new Promise((resolve, reject) => {
    if (!extensionId) {
      reject(new Error("Enter the GhostTrace extension ID to connect."));
      return;
    }
    if (!globalThis.chrome?.runtime?.sendMessage) {
      reject(new Error("This browser does not expose extension messaging on this page."));
      return;
    }
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback(value);
    };
    const timeout = window.setTimeout(() => {
      finish(reject, new Error("GhostTrace did not respond within 8 seconds. Check that the extension is enabled, reload it in chrome://extensions, then reopen the dashboard from its popup."));
    }, 8000);
    const respond = (response) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        finish(reject, new Error(runtimeError.message || "Could not reach the GhostTrace extension."));
      } else if (!response?.ok) {
        finish(reject, new Error(response?.error || "The extension rejected the request."));
      } else {
        finish(resolve, response);
      }
    };
    const message = { type, ...extra };
    try {
      if (location.protocol === "chrome-extension:" && chrome.runtime.id === extensionId) {
        chrome.runtime.sendMessage(message, respond);
      } else {
        chrome.runtime.sendMessage(extensionId, message, respond);
      }
    } catch (error) {
      finish(reject, error);
    }
  });
}

export const dashboardApi = {
  ping: (id) => extensionRequest(id, "GT_DASHBOARD_PING"),
  listSites: (id) => extensionRequest(id, "GT_DASHBOARD_LIST_SITES"),
  getSite: (id, origin) => extensionRequest(id, "GT_DASHBOARD_GET_SITE", { origin }),
  updateWorkspace: (id, origin, patch) => extensionRequest(id, "GT_DASHBOARD_UPDATE_WORKSPACE", { origin, patch }),
  setActive: (id, origin, active) => extensionRequest(id, "GT_DASHBOARD_SET_ACTIVE", { origin, active })
};
