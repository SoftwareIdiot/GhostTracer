// GhostTrace — background service worker
// Owns: per-origin activation state, captured request/response metadata,
// the evidence store, and the authorized active-verification runner.
//
// NOTE: MV3 service workers are ephemeral. All state is mirrored to
// chrome.storage.local so a worker restart does not lose evidence.

import { runDetection } from "./detectionEngine.js";

const STORE_PREFIX = "gt_evidence::";
const ACTIVE_PREFIX = "gt_active::";
const WORKSPACE_PREFIX = "gt_workspace::";
const ORIGINS_KEY = "gt_known_origins";
const EVIDENCE_URL_KEYS = new Set(["url", "targetUrl", "affected", "action", "canonicalUrl", "location", "href"]);

/** @type {Map<string, object>} in-memory evidence keyed by origin */
const evidenceCache = new Map();
const evidenceWriteQueues = new Map();
const workspaceWriteQueues = new Map();
const cookieMetadataCache = new Map();
const activeVerifyOrigins = new Set();
let originRegistryQueue = Promise.resolve();

function originOf(urlStr) {
  try {
    return new URL(urlStr).origin;
  } catch {
    return null;
  }
}

function redactEvidenceUrl(value, base) {
  try {
    const url = new URL(value, base);
    const names = [...url.searchParams.keys()];
    url.search = "";
    for (const name of names) url.searchParams.append(name, "[redacted]");
    url.username = "";
    url.password = "";
    if (url.hash) url.hash = "#present";
    return url.href;
  } catch { return String(value || ""); }
}

function redactStoredUrlFields(value) {
  let changed = false;
  const visit = (item) => {
    if (!item || typeof item !== "object") return;
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    for (const [key, child] of Object.entries(item)) {
      if (EVIDENCE_URL_KEYS.has(key) && typeof child === "string" && /^https?:/i.test(child)) {
        const safe = redactEvidenceUrl(child);
        if (safe !== child) {
          item[key] = safe;
          changed = true;
        }
      } else {
        visit(child);
      }
    }
  };
  visit(value);
  return changed;
}

function emptyEvidence(origin) {
  return {
    origin,
    createdAt: Date.now(),
    pages: {},        // url -> { title, forms:[], links:[], scripts:[], firstSeen }
    requests: [],      // captured network metadata
    domEvidence: [],   // DOM scan snapshots from content script
    verifyResults: [], // results of deliberate Module 4 checks
    passiveFindings: [], // recalculated as new evidence is captured
    notes: []
  };
}

async function getEvidence(origin) {
  if (evidenceCache.has(origin)) return evidenceCache.get(origin);
  const key = STORE_PREFIX + origin;
  const stored = await chrome.storage.local.get(key);
  const ev = stored[key] || emptyEvidence(origin);
  ev.origin ||= origin;
  ev.pages ||= {};
  ev.requests ||= [];
  ev.domEvidence ||= [];
  ev.verifyResults ||= [];
  ev.passiveFindings ||= [];
  // Older builds retained query values and shortened secret samples. Migrate
  // persisted evidence to the current metadata-only storage policy.
  let sanitized = false;
  const safePages = {};
  for (const [pageUrl, page] of Object.entries(ev.pages)) {
    const safePageUrl = redactEvidenceUrl(pageUrl);
    const safePage = { ...page };
    for (const key of ["links", "scripts"]) {
      if (Array.isArray(safePage[key])) safePage[key] = safePage[key].map((value) => {
        const safeUrl = redactEvidenceUrl(value);
        if (safeUrl !== value) sanitized = true;
        return safeUrl;
      });
    }
    if (Array.isArray(safePage.forms)) safePage.forms = safePage.forms.map((form) => {
      const action = redactEvidenceUrl(form.action || safePageUrl);
      if (action !== form.action) sanitized = true;
      return { ...form, action };
    });
    if (Array.isArray(safePage.frames)) safePage.frames = safePage.frames.map((frame) => {
      const url = redactEvidenceUrl(frame.url);
      if (url !== frame.url) sanitized = true;
      return { ...frame, url };
    });
    if (safePageUrl !== pageUrl) sanitized = true;
    const previousPage = safePages[safePageUrl];
    safePages[safePageUrl] = previousPage ? {
      ...previousPage,
      ...safePage,
      forms: [...(previousPage.forms || []), ...(safePage.forms || [])],
      links: [...new Set([...(previousPage.links || []), ...(safePage.links || [])])],
      scripts: [...new Set([...(previousPage.scripts || []), ...(safePage.scripts || [])])],
      frames: [...(previousPage.frames || []), ...(safePage.frames || [])],
      firstSeen: Math.min(previousPage.firstSeen || Date.now(), safePage.firstSeen || Date.now())
    } : safePage;
  }
  ev.pages = safePages;
  for (const request of ev.requests) {
    const safeUrl = redactEvidenceUrl(request.url);
    if (safeUrl !== request.url) { request.url = safeUrl; sanitized = true; }
    if (request.responseHeaders?.location) {
      const safeLocation = redactEvidenceUrl(request.responseHeaders.location, request.url);
      if (safeLocation !== request.responseHeaders.location) { request.responseHeaders.location = safeLocation; sanitized = true; }
    }
  }
  for (const dom of ev.domEvidence || []) {
    if (dom.url) {
      const safeUrl = redactEvidenceUrl(dom.url);
      if (safeUrl !== dom.url) { dom.url = safeUrl; sanitized = true; }
    }
    for (const hit of dom.reflectedParams || []) {
      if (Object.hasOwn(hit, "valueSample")) {
        delete hit.valueSample;
        sanitized = true;
      }
    }
    for (const secret of dom.secretsCandidates || []) {
      if (Object.hasOwn(secret, "sample")) { delete secret.sample; sanitized = true; }
    }
    if (Array.isArray(dom.forms)) dom.forms = dom.forms.map((form) => {
      const action = redactEvidenceUrl(form.action || dom.url);
      if (action !== form.action) sanitized = true;
      return { ...form, action };
    });
    for (const key of ["links", "scripts"]) {
      if (Array.isArray(dom[key])) dom[key] = dom[key].map((value) => {
        const safeUrl = redactEvidenceUrl(value);
        if (safeUrl !== value) sanitized = true;
        return safeUrl;
      });
    }
    if (Array.isArray(dom.frames)) dom.frames = dom.frames.map((frame) => {
      const url = redactEvidenceUrl(frame.url);
      if (url !== frame.url) sanitized = true;
      return { ...frame, url };
    });
  }
  for (const result of [...ev.verifyResults, ...(ev.scanFindings || []), ...(ev.passiveFindings || [])]) {
    for (const key of ["targetUrl", "affected"]) {
      if (typeof result[key] !== "string" || !/^https?:/i.test(result[key])) continue;
      const safeUrl = redactEvidenceUrl(result[key]);
      if (safeUrl !== result[key]) { result[key] = safeUrl; sanitized = true; }
    }
  }
  if (redactStoredUrlFields(ev)) sanitized = true;
  if (sanitized) await chrome.storage.local.set({ [key]: ev });
  evidenceCache.set(origin, ev);
  return ev;
}

async function saveEvidence(origin) {
  const ev = evidenceCache.get(origin);
  if (!ev) return;
  await chrome.storage.local.set({ [STORE_PREFIX + origin]: ev });
}

async function enqueueEvidenceWrite(origin, action) {
  const previous = evidenceWriteQueues.get(origin) || Promise.resolve();
  const write = previous.catch(() => {}).then(async () => {
    const result = await action();
    const evidence = await getEvidence(origin);
    const cookies = await getCookieMetadata(origin);
    evidence.passiveFindings = runDetection({ ...evidence, cookies });
    await saveEvidence(origin);
    broadcastUpdate(origin);
    return result;
  });
  evidenceWriteQueues.set(origin, write);
  try {
    return await write;
  } finally {
    if (evidenceWriteQueues.get(origin) === write) evidenceWriteQueues.delete(origin);
  }
}

async function getCookieMetadata(origin) {
  const cached = cookieMetadataCache.get(origin);
  if (cached && Date.now() - cached.cachedAt < 4000) return cached.cookies;
  try {
    const hostname = new URL(origin).hostname;
    const rawCookies = await chrome.cookies.getAll({ domain: hostname });
    const cookies = rawCookies.map((cookie) => ({
      name: cookie.name, domain: cookie.domain, path: cookie.path,
      secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite,
      session: cookie.session, expirationDate: cookie.expirationDate || null
    }));
    cookieMetadataCache.set(origin, { cookies, cachedAt: Date.now() });
    return cookies;
  } catch { return []; }
}

async function isActive(origin) {
  const key = ACTIVE_PREFIX + origin;
  const stored = await chrome.storage.local.get(key);
  return !!stored[key];
}

async function setActive(origin, active) {
  await chrome.storage.local.set({ [ACTIVE_PREFIX + origin]: !!active });
  const update = originRegistryQueue.catch(() => {}).then(async () => {
    const known = await getKnownOrigins();
    if (!known.includes(origin)) await chrome.storage.local.set({ [ORIGINS_KEY]: [...known, origin] });
  });
  originRegistryQueue = update;
  await update;
  if (active) await injectObserverIntoOpenTabs(origin);
}

async function injectObserverIntoOpenTabs(origin) {
  try {
    const tabs = await chrome.tabs.query({});
    const matches = tabs.filter((tab) => tab.id != null && originOf(tab.url) === origin);
    await Promise.all(matches.map(async (tab) => {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["content/content-script.js"]
        });
      } catch {
        // Some browser-owned or restricted pages cannot accept an injection.
        // Other matching tabs and the next normal navigation still work.
      }
    }));
  } catch {
    // Activation itself should still succeed if tab injection is unavailable.
  }
}

async function getKnownOrigins() {
  const saved = await chrome.storage.local.get(ORIGINS_KEY);
  if (Array.isArray(saved[ORIGINS_KEY])) return saved[ORIGINS_KEY];
  // One-time migration for sites activated before the dashboard registry existed.
  const all = await chrome.storage.local.get(null);
  const origins = new Set();
  for (const key of Object.keys(all)) {
    if (key.startsWith(ACTIVE_PREFIX) || key.startsWith(STORE_PREFIX) || key.startsWith(WORKSPACE_PREFIX)) {
      origins.add(key.slice(key.indexOf("::") + 2));
    }
  }
  const migrated = [...origins];
  await chrome.storage.local.set({ [ORIGINS_KEY]: migrated });
  return migrated;
}

function validateSiteOrigin(origin) {
  try {
    const url = new URL(origin);
    if (!/^https?:$/.test(url.protocol) || url.origin !== origin) return null;
    return url.origin;
  } catch {
    return null;
  }
}

async function listDashboardSites() {
  const origins = await getKnownOrigins();
  return Promise.all(origins.map(async (origin) => {
    const evidence = await getEvidence(origin);
    const workspace = await getWorkspace(origin);
    const latestRequest = evidence.requests.reduce((latest, request) => Math.max(latest, request.timeStamp || 0), 0);
    const latestDom = evidence.domEvidence.reduce((latest, item) => Math.max(latest, item.timestamp || 0), 0);
    return {
      origin,
      active: await isActive(origin),
      pageCount: Object.keys(evidence.pages || {}).length,
      requestCount: (evidence.requests || []).length,
      findingCount: (workspace.manualFindings || []).length,
      lastSeen: Math.max(latestRequest, latestDom, evidence.createdAt || 0),
      title: Object.values(evidence.pages || {}).find((page) => page.title)?.title || ""
    };
  }));
}

async function getDashboardSite(origin) {
  const evidence = await getEvidence(origin);
  const workspace = await getWorkspace(origin);
  const cookies = await getCookieMetadata(origin);
  return { origin, active: await isActive(origin), evidence, workspace, cookies };
}

async function getWorkspace(origin) {
  const key = WORKSPACE_PREFIX + origin;
  const stored = await chrome.storage.local.get(key);
  return stored[key] || { reviews: {}, manualFindings: [], notes: "", updatedAt: null };
}

async function updateWorkspace(origin, patch) {
  const previous = workspaceWriteQueues.get(origin) || Promise.resolve();
  const write = previous.catch(() => {}).then(async () => {
    const current = await getWorkspace(origin);
    const next = { ...current, ...patch, updatedAt: Date.now() };
    await chrome.storage.local.set({ [WORKSPACE_PREFIX + origin]: next });
    return next;
  });
  workspaceWriteQueues.set(origin, write);
  try {
    return await write;
  } finally {
    if (workspaceWriteQueues.get(origin) === write) workspaceWriteQueues.delete(origin);
  }
}

// ---------------------------------------------------------------------------
// webRequest capture (read-only — fires only while the origin is activated)
// ---------------------------------------------------------------------------

const MAX_REQUESTS_PER_ORIGIN = 500;
const pendingHeaders = new Map(); // requestId -> partial record

// Everything in this block is wrapped in try/catch: webRequest listener
// registration can throw synchronously (e.g. a missing filter argument),
// and in an unguarded top-level script that would silently abort every
// listener registration below it — including onMessage, which is how a
// single typo here previously made the entire popup/panel hang forever.
try {
  registerWebRequestListeners();
} catch (e) {
  console.error("GhostTrace: failed to register webRequest listeners", e);
}

function registerWebRequestListeners() {
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Requests initiated by GhostTrace's own extension pages are active
    // verification traffic, not target-generated passive evidence.
    if (details.initiator?.startsWith(`chrome-extension://${chrome.runtime.id}`)) return;
    const origin = originOf(details.url);
    if (!origin) return;
    pendingHeaders.set(details.requestId, {
      id: details.requestId,
      url: redactEvidenceUrl(details.url),
      method: details.method,
      type: details.type,
      tabId: details.tabId,
      timeStamp: details.timeStamp,
      origin,
      requestBodyPresent: !!details.requestBody,
      // We only record whether a body was present and its approximate shape,
      // never raw credential values, to keep this a metadata-level recon tool.
      requestBodyKeys: extractBodyKeys(details.requestBody)
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

function extractBodyKeys(requestBody) {
  if (!requestBody) return [];
  try {
    if (requestBody.formData) return Object.keys(requestBody.formData);
    if (requestBody.raw) return ["<raw-bytes>"];
  } catch {
    /* ignore */
  }
  return [];
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const rec = pendingHeaders.get(details.requestId);
    if (!rec) return;
    rec.requestHeaders = (details.requestHeaders || []).map((h) => h.name);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    const rec = pendingHeaders.get(details.requestId);
    if (!rec) return;
    const origin = rec.origin;
    if (!(await isActive(origin))) {
      pendingHeaders.delete(details.requestId);
      return;
    }
    rec.status = details.statusCode;
    const safeHeaders = new Set([
      "content-security-policy", "content-security-policy-report-only", "x-frame-options",
      "strict-transport-security", "x-content-type-options", "referrer-policy",
      "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
      "cross-origin-embedder-policy", "content-type", "cache-control", "server",
      "x-powered-by", "location"
    ]);
    rec.responseHeaders = (details.responseHeaders || []).reduce((acc, h) => {
      const name = h.name.toLowerCase();
      // Cookie values are deliberately kept out of the evidence store. Cookie
      // configuration is collected separately as flags and names only.
      if (!safeHeaders.has(name) || name === "set-cookie" || name === "set-cookie2") return acc;
      acc[name] = name === "location" ? redactEvidenceUrl(h.value, rec.url) : h.value;
      return acc;
    }, {});

    await enqueueEvidenceWrite(origin, async () => {
      if (!(await isActive(origin))) return;
      const ev = await getEvidence(origin);
      ev.requests.push(rec);
      if (ev.requests.length > MAX_REQUESTS_PER_ORIGIN) {
        ev.requests.splice(0, ev.requests.length - MAX_REQUESTS_PER_ORIGIN);
      }
    });
    pendingHeaders.delete(details.requestId);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.webRequest.onCompleted.addListener(() => {}, { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(
  (d) => pendingHeaders.delete(d.requestId),
  { urls: ["<all_urls>"] }
);
} // end registerWebRequestListeners

// ---------------------------------------------------------------------------
// Message bus — content scripts, popup, and the devtools panel all talk here
// ---------------------------------------------------------------------------

const panelPorts = new Set();

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "gt-panel") {
    panelPorts.add(port);
    port.onDisconnect.addListener(() => panelPorts.delete(port));
  }
});

function broadcastUpdate(origin) {
  for (const port of panelPorts) {
    try {
      port.postMessage({ type: "GT_EVIDENCE_UPDATED", origin });
    } catch {
      /* port may be stale */
    }
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender)
    .then(sendResponse)
    .catch((err) => {
      // Never let an unexpected error leave the sender's promise hanging
      // forever — always resolve the channel, even on failure.
      console.error("GhostTrace background error handling", msg && msg.type, err);
      sendResponse({ ok: false, error: String(err) });
    });
  return true; // keep the message channel open for the async response
});

// Local companion dashboard bridge. Access is restricted both by
// externally_connectable in manifest.json and this exact origin check.
const DASHBOARD_ORIGINS = new Set([
  "http://localhost:5173", "http://127.0.0.1:5173",
  "http://localhost:3000", "http://127.0.0.1:3000"
]);
chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  let senderOrigin = "";
  let senderPath = "";
  try {
    const senderUrl = new URL(sender.url);
    senderOrigin = senderUrl.origin;
    senderPath = senderUrl.pathname;
  } catch { /* reject below */ }
  if (!DASHBOARD_ORIGINS.has(senderOrigin) || senderPath !== "/dashboard.html") {
    sendResponse({ ok: false, error: "Dashboard origin is not allowed." });
    return false;
  }
  handleDashboardMessage(msg)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

async function handleDashboardMessage(msg) {
  switch (msg?.type) {
    case "GT_DASHBOARD_PING":
      return { ok: true, extensionId: chrome.runtime.id, version: chrome.runtime.getManifest().version };
    case "GT_DASHBOARD_LIST_SITES":
      return { ok: true, sites: await listDashboardSites() };
    case "GT_DASHBOARD_GET_SITE": {
      const origin = validateSiteOrigin(msg.origin);
      if (!origin || !(await getKnownOrigins()).includes(origin)) return { ok: false, error: "Site is not in the activated-site list." };
      return { ok: true, site: await getDashboardSite(origin) };
    }
    case "GT_DASHBOARD_UPDATE_WORKSPACE": {
      const origin = validateSiteOrigin(msg.origin);
      if (!origin || !(await getKnownOrigins()).includes(origin)) return { ok: false, error: "Site is not in the activated-site list." };
      return { ok: true, workspace: await updateWorkspace(origin, msg.patch || {}) };
    }
    case "GT_DASHBOARD_SET_ACTIVE": {
      const origin = validateSiteOrigin(msg.origin);
      if (!origin || !(await getKnownOrigins()).includes(origin)) return { ok: false, error: "Site is not in the activated-site list." };
      await setActive(origin, !!msg.active);
      broadcastUpdate(origin);
      return { ok: true, active: !!msg.active };
    }
    default:
      return { ok: false, error: "Unknown dashboard request." };
  }
}

async function handleMessage(msg, sender) {
  switch (msg.type) {
    case "GT_GET_STATE": {
      const origin = msg.origin || originOf(sender?.tab?.url);
      return { active: await isActive(origin), origin };
    }

    case "GT_SET_ACTIVE": {
      await setActive(msg.origin, msg.active);
      if (msg.active) await getEvidence(msg.origin); // ensure store exists
      broadcastUpdate(msg.origin);
      return { ok: true };
    }

    case "GT_DOM_EVIDENCE": {
      const origin = msg.origin;
      if (!(await isActive(origin))) return { ok: false, reason: "inactive" };
      return await enqueueEvidenceWrite(origin, async () => {
        if (!(await isActive(origin))) return { ok: false, reason: "inactive" };
        const ev = await getEvidence(origin);
        ev.domEvidence.push({ ...msg.payload, timestamp: Date.now() });
        if (ev.domEvidence.length > 200) ev.domEvidence.splice(0, ev.domEvidence.length - 200);

        const pageUrl = msg.payload.url;
        ev.pages[pageUrl] = {
          title: msg.payload.title,
          urlMetadata: msg.payload.urlMetadata || {},
          documentMetadata: msg.payload.documentMetadata || {},
          forms: msg.payload.forms,
          links: msg.payload.links,
          scripts: msg.payload.scripts,
          frames: msg.payload.frames || [],
          technologyHints: msg.payload.technologyHints || [],
          storageMetadata: msg.payload.storageMetadata || {},
          reflectedParams: msg.payload.reflectedParams || [],
          secretsCandidates: msg.payload.secretsCandidates || [],
          firstSeen: ev.pages[pageUrl]?.firstSeen || Date.now()
        };
        return { ok: true };
      });
    }
    
    case "GT_GET_EVIDENCE": {
      return await getEvidence(msg.origin);
    }

    case "GT_GET_WORKSPACE": {
      return await getWorkspace(msg.origin);
    }

    case "GT_UPDATE_WORKSPACE": {
      return await updateWorkspace(msg.origin, msg.patch || {});
    }

    case "GT_CLEAR_EVIDENCE": {
      return await enqueueEvidenceWrite(msg.origin, async () => {
        evidenceCache.set(msg.origin, emptyEvidence(msg.origin));
        return { ok: true };
      });
    }

    case "GT_GET_COOKIES": {
      try {
        const cookies = await chrome.cookies.getAll({ domain: new URL(msg.origin).hostname });
        return cookies.map((c) => ({
          name: c.name,
          domain: c.domain,
          path: c.path,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite,
          session: c.session,
          expirationDate: c.expirationDate || null
        }));
      } catch (e) {
        return { error: String(e) };
      }
    }

    case "GT_RUN_VERIFY": {
      const origin = validateSiteOrigin(msg.origin);
      const extensionPrefix = `chrome-extension://${chrome.runtime.id}/`;
      if (!origin || !sender?.url?.startsWith(extensionPrefix) || sender.tab) {
        return { ok: false, error: "Verification can only be started from GhostTrace's extension interface." };
      }
      if (activeVerifyOrigins.has(origin)) return { ok: false, error: "A verification run is already active for this site." };
      activeVerifyOrigins.add(origin);
      try {
        const result = await runVerifyTest(origin, msg.test || {});
        return await enqueueEvidenceWrite(origin, async () => {
          const ev = await getEvidence(origin);
          ev.verifyResults.push(result);
          return result;
        });
      } finally {
        activeVerifyOrigins.delete(origin);
      }
    }

    default:
      if (msg?.type?.startsWith("GT_DASHBOARD_")) return await handleDashboardMessage(msg);
      return { ok: false, reason: "unknown_message_type" };
  }
}

// ---------------------------------------------------------------------------
// Module 4: Verify — controlled, explicit, tester-initiated active tests.
// Each test is opt-in per finding and never auto-chains into further tests.
// ---------------------------------------------------------------------------

async function runVerifyTest(origin, test) {
  const base = {
    id: crypto.randomUUID(),
    testType: test.type,
    targetUrl: test.type === "reflected-query-scan" ? redactQueryValues(test.url) : test.url,
    timestamp: Date.now(),
    origin
  };

  try {
    const authorizedOrigin = new URL(origin).origin;
    const target = new URL(test.url);
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      return { ...base, ok: false, summary: "Verification is limited to HTTP(S) URLs." };
    }
    if (target.origin !== authorizedOrigin) {
      return { ...base, ok: false, summary: `Blocked: this test targets ${target.origin}, while the activated assessment scope is ${authorizedOrigin}. Activate that origin separately before testing it.` };
    }
    if (!(await isActive(authorizedOrigin))) {
      return { ...base, ok: false, summary: "Blocked: observation is paused for this origin. Activate it before running a verification test." };
    }
    switch (test.type) {
      case "reflected-input":
        return { ...base, ...(await testReflectedInput(test)) };
      case "reflected-query-scan":
        return { ...base, ...(await scanQueryParameters(test)) };
      case "open-redirect":
        return { ...base, ...(await testOpenRedirect(test)) };
      case "idor-object-auth":
        return { ...base, ...(await testIdor(test)) };
      case "security-header-behavior":
        return { ...base, ...(await testHeaderBehavior(test)) };
      default:
        return { ...base, ok: false, summary: "Unknown test type." };
    }
  } catch (e) {
    return { ...base, ok: false, summary: `Test failed to execute: ${String(e)}` };
  }
}

const MARKER = "GT_MARK_"; // benign, non-executing marker used for reflection checks
const QUERY_SCAN_MAX_PARAMS = 10;
const QUERY_SCAN_DELAY_MS = 500;
const QUERY_SCAN_BODY_LIMIT = 1024 * 1024;
const QUERY_SCAN_TIMEOUT_MS = 15000;
const QUERY_SCAN_MAX_DURATION_MS = 90000;
const SENSITIVE_QUERY_PARAM = /(?:token|auth|session|secret|password|passwd|csrf|xsrf|signature|api[_-]?key|access[_-]?key|client[_-]?secret|^sig$|^key$|^code$)/i;

function redactQueryValues(value) {
  try {
    const url = new URL(value);
    const redactedEntries = [...url.searchParams.keys()].map((key) => [key, "[redacted]"]);
    url.search = "";
    for (const [key, replacement] of redactedEntries) url.searchParams.append(key, replacement);
    return url.toString();
  } catch {
    return "[invalid URL]";
  }
}

async function scanQueryParameters({ url: rawUrl }) {
  const url = new URL(rawUrl);
  const names = [...new Set(url.searchParams.keys())];
  const excludedParameters = names.filter((name) => SENSITIVE_QUERY_PARAM.test(name));
  const parameters = names.filter((name) => !SENSITIVE_QUERY_PARAM.test(name)).slice(0, QUERY_SCAN_MAX_PARAMS);
  if (parameters.length === 0) {
    return {
      ok: true,
      summary: excludedParameters.length
        ? "No query parameters were scanned. Parameters with names associated with credentials or anti-CSRF values are excluded."
        : "This observed URL has no query parameters to scan.",
      maxParameters: QUERY_SCAN_MAX_PARAMS,
      delayMs: QUERY_SCAN_DELAY_MS,
      excludedParameters,
      scanItems: []
    };
  }

  let lastRequestFinished = 0;
  const scanDeadline = Date.now() + QUERY_SCAN_MAX_DURATION_MS;
  const request = async (targetUrl) => {
    if (Date.now() >= scanDeadline) throw new Error("Scan time limit reached.");
    if (lastRequestFinished) {
      const remaining = QUERY_SCAN_DELAY_MS - (Date.now() - lastRequestFinished);
      if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
    }
    if (Date.now() >= scanDeadline) throw new Error("Scan time limit reached.");
    try {
      return await readScanResponse(targetUrl, Math.min(QUERY_SCAN_TIMEOUT_MS, scanDeadline - Date.now()));
    } finally {
      lastRequestFinished = Date.now();
    }
  };

  let baseline;
  try {
    baseline = await request(url.toString());
  } catch (error) {
    return {
      ok: false,
      summary: safeScanError(error),
      maxParameters: QUERY_SCAN_MAX_PARAMS,
      delayMs: QUERY_SCAN_DELAY_MS,
      excludedParameters,
      scanItems: []
    };
  }

  const scanItems = [];
  for (const parameter of parameters) {
    const marker = `${MARKER}${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const candidateUrl = new URL(url);
    candidateUrl.searchParams.set(parameter, marker);
    let candidate;
    try {
      candidate = await request(candidateUrl.toString());
    } catch (error) {
      scanItems.push({
        parameter,
        payload: marker,
        severity: "info",
        confidence: "inconclusive",
        xssConfirmed: false,
        baseline: responseSummary(baseline),
        anomalousResponse: null,
        diff: null,
        error: safeScanError(error)
      });
      continue;
    }

    const reflected = candidate.text.includes(marker);
    const item = {
      parameter,
      payload: marker,
      severity: "info",
      confidence: reflected ? "pending-retest" : "not-observed",
      xssConfirmed: false,
      baseline: responseSummary(baseline),
      anomalousResponse: {
        ...responseSummary(candidate),
        markerReflected: reflected,
        reflectionContext: reflected ? classifyReflectionContext(candidate.text, candidate.text.indexOf(marker), candidate.contentType) : null
      },
      diff: responseDiff(baseline, candidate)
    };

    if (reflected) {
      const retestMarker = `${MARKER}${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
      const retestUrl = new URL(url);
      retestUrl.searchParams.set(parameter, retestMarker);
      try {
        const retest = await request(retestUrl.toString());
        const retestReflected = retest.text.includes(retestMarker);
        item.retest = {
          payload: retestMarker,
          ...responseSummary(retest),
          markerReflected: retestReflected,
          reflectionContext: retestReflected ? classifyReflectionContext(retest.text, retest.text.indexOf(retestMarker), retest.contentType) : null
        };
        item.confidence = retestReflected ? "high for repeatable reflection" : "low; not repeated";
      } catch (error) {
        item.retest = { payload: retestMarker, error: safeScanError(error), markerReflected: false };
        item.confidence = "low; re-test failed";
      }
    }
    scanItems.push(item);
  }

  const reflectedCount = scanItems.filter((item) => item.anomalousResponse?.markerReflected).length;
  const repeatedCount = scanItems.filter((item) => item.anomalousResponse?.markerReflected && item.retest?.markerReflected).length;
  return {
    ok: true,
    summary: `Scanned ${parameters.length} of ${names.length} query parameters against the observed page. ${reflectedCount} reflected a harmless marker; ${repeatedCount} repeated on re-test. Reflection is not proof of XSS.`,
    maxParameters: QUERY_SCAN_MAX_PARAMS,
    delayMs: QUERY_SCAN_DELAY_MS,
    excludedParameters,
    omittedParameters: names.filter((name) => !excludedParameters.includes(name) && !parameters.includes(name)),
    baseline: responseSummary(baseline),
    scanItems
  };
}

async function readScanResponse(url, timeoutMs = QUERY_SCAN_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = performance.now();
  try {
    const response = await fetch(url, {
      credentials: "include",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    });
    const reader = response.body?.getReader();
    const chunks = [];
    let bytes = 0;
    let truncated = false;
    if (reader) {
      while (bytes < QUERY_SCAN_BODY_LIMIT) {
        const { done, value } = await reader.read();
        if (done) break;
        const remaining = QUERY_SCAN_BODY_LIMIT - bytes;
        if (value.byteLength > remaining) {
          chunks.push(value.subarray(0, remaining));
          bytes += remaining;
          truncated = true;
          await reader.cancel();
          break;
        }
        chunks.push(value);
        bytes += value.byteLength;
      }
      if (bytes >= QUERY_SCAN_BODY_LIMIT) truncated = true;
    }
    const body = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    return {
      status: response.status,
      responseLength: bytes,
      truncated,
      durationMs: Math.round(performance.now() - startedAt),
      contentType: response.headers.get("content-type") || "",
      text: new TextDecoder().decode(body)
    };
  } finally {
    clearTimeout(timeout);
  }
}

function responseSummary(response) {
  return { status: response.status, responseLength: response.responseLength, truncated: response.truncated, durationMs: response.durationMs, contentType: response.contentType };
}

function responseDiff(baseline, candidate) {
  return {
    statusChanged: baseline.status !== candidate.status,
    responseLengthDelta: candidate.responseLength - baseline.responseLength,
    durationDeltaMs: candidate.durationMs - baseline.durationMs,
    responseTruncated: baseline.truncated || candidate.truncated
  };
}

function safeScanError(error) {
  if (error?.message === "Scan time limit reached.") return "Scan stopped at the 90-second time limit.";
  return error?.name === "AbortError"
    ? `Request timed out after ${QUERY_SCAN_TIMEOUT_MS / 1000} seconds.`
    : "Request failed or was blocked (network, CORS, or redirect). No response body was retained.";
}

async function testReflectedInput({ url, param }) {
  const marker = MARKER + Math.random().toString(36).slice(2, 10);
  const u = new URL(url);
  u.searchParams.set(param, marker);
  const resp = await fetch(u.toString(), { credentials: "include", redirect: "error" });
  const text = await resp.text();
  const markerIndex = text.indexOf(marker);
  const reflected = markerIndex !== -1;
  const contentType = resp.headers.get("content-type") || "";
  const reflectionContext = reflected ? classifyReflectionContext(text, markerIndex, contentType) : null;
  return {
    ok: true,
    reflected,
    marker,
    contentType,
    status: resp.status,
    responseLength: text.length,
    reflectionContext,
    summary: reflected
      ? `A harmless marker for parameter "${param}" appeared in the HTTP ${resp.status} response (${reflectionContext}; ${contentType || "content type unavailable"}). This confirms reflection only; no executable payload was sent and XSS is not confirmed.`
      : `A harmless marker for parameter "${param}" was not found in the response body (HTTP ${resp.status}; ${contentType || "content type unavailable"}). This does not rule out client-side or encoded reflection.`
  };
}

function classifyReflectionContext(text, index, contentType) {
  const before = text.slice(0, index);
  const scriptOpen = before.toLowerCase().lastIndexOf("<script");
  const scriptClose = before.toLowerCase().lastIndexOf("</script");
  if (scriptOpen > scriptClose) return "inside a script element";
  const styleOpen = before.toLowerCase().lastIndexOf("<style");
  const styleClose = before.toLowerCase().lastIndexOf("</style");
  if (styleOpen > styleClose) return "inside a style element";
  const lastOpen = before.lastIndexOf("<");
  const lastClose = before.lastIndexOf(">");
  if (lastOpen > lastClose) return "inside HTML tag markup or an attribute";
  return /html/i.test(contentType) ? "in HTML text content" : "in a non-HTML response body";
}

async function testOpenRedirect({ url, param }) {
  const safeTestDomain = "https://ghosttrace.invalid/verify-marker";
  const u = new URL(url);
  u.searchParams.set(param, safeTestDomain);
  const resp = await fetch(u.toString(), { credentials: "include", redirect: "manual" });
  const location = resp.headers.get("location");
  const isRedirectStatus = resp.status >= 300 && resp.status < 400;
  const redirectsToTestDomain = !!location && location.includes("ghosttrace.invalid");
  return {
    ok: true,
    status: resp.status,
    location,
    redirectsToTestDomain,
    summary: redirectsToTestDomain
      ? `Server issued a ${resp.status} redirect to the attacker-controlled test value supplied in "${param}". This indicates an unvalidated/open redirect.`
      : `No redirect to the injected test domain was observed (status ${resp.status}).`
  };
}

async function testIdor({ url, baselineId, candidateId }) {
  const baselineUrl = url.replace(String(baselineId), String(baselineId));
  const candidateUrl = url.replace(String(baselineId), String(candidateId));
  const [baseResp, candResp] = await Promise.all([
    fetch(baselineUrl, { credentials: "include" }),
    fetch(candidateUrl, { credentials: "include" })
  ]);
  const baseStatus = baseResp.status;
  const candStatus = candResp.status;
  const candText = await candResp.text();
  const likelyAccessible = candStatus >= 200 && candStatus < 300 && candText.length > 0;
  return {
    ok: true,
    baseStatus,
    candStatus,
    likelyAccessible,
    summary: likelyAccessible
      ? `Requesting object id "${candidateId}" (not owned by the test account used for "${baselineId}") returned HTTP ${candStatus} with body content. This is a strong signal of missing object-level authorization — confirm by inspecting the returned data for another tenant's information.`
      : `Candidate id "${candidateId}" returned HTTP ${candStatus}; no clear evidence of unauthorized access from status code alone.`
  };
}

async function testHeaderBehavior({ url }) {
  const resp = await fetch(url, { credentials: "include" });
  const headers = {};
  resp.headers.forEach((v, k) => (headers[k] = v));
  const missing = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy"
  ].filter((h) => !headers[h]);
  return {
    ok: true,
    headers,
    missing,
    summary: missing.length
      ? `Re-requested the endpoint directly and confirmed these security headers are absent on the live response: ${missing.join(", ")}.`
      : "All commonly expected security headers were present on direct re-request."
  };
}

// Clean up evidence when a tab navigates away from the activated origin is
// intentionally NOT automatic — testers typically want evidence to persist
// across a session. Use "Clear evidence" in the panel to reset.
chrome.webNavigation.onCompleted.addListener(() => {});
