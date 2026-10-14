(async function () {
  const originEl = document.getElementById("origin");
  const toggleEl = document.getElementById("toggle");
  const statusEl = document.getElementById("status");
  const dashboardEl = document.getElementById("open-dashboard");
  let active = false;

  function sendMessage(message, timeoutMs = 6000) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        callback(value);
      };
      timer = window.setTimeout(() => finish(reject, new Error("GhostTrace did not answer. Reload it from chrome://extensions and retry.")), timeoutMs);
      try {
        chrome.runtime.sendMessage(message, (response) => {
          const runtimeError = chrome.runtime.lastError;
          if (runtimeError) finish(reject, new Error(runtimeError.message));
          else if (response === undefined) finish(reject, new Error("GhostTrace returned no response. Reload the extension and retry."));
          else finish(resolve, response);
        });
      } catch (error) { finish(reject, error); }
    });
  }

  dashboardEl.addEventListener("click", openDashboard);

  async function openDashboard() {
    dashboardEl.disabled = true;
    try {
      const query = `?extensionId=${encodeURIComponent(chrome.runtime.id)}`;
      const devUrl = `http://127.0.0.1:5173/dashboard.html${query}`;
      let destination = `${chrome.runtime.getURL("panel/dist/dashboard.html")}${query}`;
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 1200);
      try {
        const response = await fetch(devUrl, { method: "HEAD", cache: "no-store", signal: controller.signal });
        if (response.ok) destination = devUrl;
      } catch { /* Use the packaged dashboard when the local Vite server is stopped. */ }
      finally { window.clearTimeout(timeout); }
      chrome.tabs.create({ url: destination }, () => window.close());
    } catch (error) {
      dashboardEl.disabled = false;
      statusEl.textContent = `Could not open dashboard: ${error?.message || error}`;
    }
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    originEl.textContent = "Not an http(s) page";
    toggleEl.disabled = true;
    statusEl.textContent = "Observation is available on HTTP(S) pages.";
    return;
  }

  const origin = new URL(tab.url).origin;
  originEl.textContent = origin;

  function render(isActive) {
    active = isActive;
    toggleEl.disabled = false;
    toggleEl.textContent = active ? "Pause observation" : "Activate observation";
    toggleEl.className = active ? "active" : "";
    statusEl.innerHTML = active
      ? '<span class="dot on"></span>Observation active · passive checks update while you browse'
      : '<span class="dot off"></span>Observation inactive';
  }

  async function refresh() {
    toggleEl.disabled = true;
    toggleEl.textContent = "Checking…";
    try {
      const state = await sendMessage({ type: "GT_GET_STATE", origin });
      if (state?.error) throw new Error(state.error);
      render(!!state?.active);
    } catch (error) {
      toggleEl.disabled = false;
      toggleEl.textContent = "Retry status";
      statusEl.textContent = `Could not read observation status: ${error?.message || error}`;
    }
  }

  toggleEl.addEventListener("click", async () => {
    if (toggleEl.textContent === "Retry status") { await refresh(); return; }
    toggleEl.disabled = true;
    try {
      const result = await sendMessage({ type: "GT_SET_ACTIVE", origin, active: !active });
      if (!result?.ok) throw new Error(result?.error || "Could not update observation status.");
      render(!active);
    } catch (error) {
      toggleEl.disabled = false;
      statusEl.textContent = `Could not update observation: ${error?.message || error}`;
    }
  });

  refresh();
})();
