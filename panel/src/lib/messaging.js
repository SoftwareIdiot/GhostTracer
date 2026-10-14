// Bridges the DevTools panel (which inspects a specific tab) to the
// background service worker (which owns the evidence store).

export function getInspectedOrigin() {
  return new Promise((resolve) => {
    chrome.devtools.inspectedWindow.eval("location.origin", (result, exc) => {
      if (exc || !result) resolve(null);
      else resolve(result);
    });
  });
}

export function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra });
}

export const api = {
  getState: (origin) => send("GT_GET_STATE", { origin }),
  setActive: (origin, active) => send("GT_SET_ACTIVE", { origin, active }),
  getEvidence: (origin) => send("GT_GET_EVIDENCE", { origin }),
  getWorkspace: (origin) => send("GT_GET_WORKSPACE", { origin }),
  updateWorkspace: (origin, patch) => send("GT_UPDATE_WORKSPACE", { origin, patch }),
  clearEvidence: (origin) => send("GT_CLEAR_EVIDENCE", { origin }),
  getCookies: (origin) => send("GT_GET_COOKIES", { origin }),
  runVerify: (origin, test) => send("GT_RUN_VERIFY", { origin, test }),
};

/**
 * Keeps a long-lived port open to the background worker so the panel can
 * react live as new evidence (requests, DOM scans, verify results) arrives.
 */
export function subscribeToUpdates(onEvent) {
  const port = chrome.runtime.connect({ name: "gt-panel" });
  port.onMessage.addListener((msg) => onEvent(msg));
  return () => port.disconnect();
}
