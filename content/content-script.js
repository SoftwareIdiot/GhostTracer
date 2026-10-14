// Passive, read-only page observation. GhostTrace sends structural metadata
// only: no form values, cookie values, query values, or storage values.
(async function ghostTraceObserve() {
  if (globalThis.__ghostTraceObserverV1) return;
  globalThis.__ghostTraceObserverV1 = true;
  const origin = location.origin;
  const activeKey = `gt_active::${origin}`;
  let active = false;
  let started = false;
  let routeObserver = null;
  let routeTimer = null;

  const capture = () => {
    if (!active) return;
    const url = safeUrl(location.href);
    const payload = {
      url,
      origin,
      title: document.title,
      urlMetadata: collectUrlMetadata(),
      documentMetadata: collectDocumentMetadata(),
      forms: collectForms(),
      links: collectLinks(),
      scripts: collectScripts(),
      frames: collectFrames(),
      technologyHints: collectTechnologyHints(),
      storageMetadata: collectStorageMetadata(),
      reflectedParams: findReflectedUrlParams(),
      secretsCandidates: scanForExposedSecrets()
    };
    chrome.runtime.sendMessage({ type: "GT_DOM_EVIDENCE", origin, payload }).catch(() => {});
  };

  let lastHref = location.href;
  const checkRoute = () => {
    if (!active) return;
    if (location.href === lastHref) return;
    lastHref = location.href;
    clearTimeout(routeTimer);
    routeTimer = setTimeout(capture, 350);
  };

  const start = () => {
    if (!active || started) return;
    started = true;
    lastHref = location.href;
    capture();
    // Keep one observer for SPA route changes; do not create a new observer for
    // each navigation. Debouncing avoids repeatedly walking large documents.
    routeObserver = new MutationObserver(checkRoute);
    routeObserver.observe(document, { subtree: true, childList: true });
    window.addEventListener("popstate", checkRoute);
    window.addEventListener("hashchange", checkRoute);
  };

  const stop = () => {
    active = false;
    started = false;
    routeObserver?.disconnect();
    routeObserver = null;
    clearTimeout(routeTimer);
    window.removeEventListener("popstate", checkRoute);
    window.removeEventListener("hashchange", checkRoute);
  };

  // Activation changes are delivered to already-open pages, so starting or
  // pausing observation does not need to reload the target or interrupt work.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local" || !Object.hasOwn(changes, activeKey)) return;
    active = !!changes[activeKey].newValue;
    if (active) start();
    else stop();
  });

  try {
    const state = await chrome.runtime.sendMessage({ type: "GT_GET_STATE", origin });
    active = !!state?.active;
    start();
  } catch {
    // The page remains idle if the extension worker is unavailable.
  }
})();

function safeUrl(value) {
  try {
    const url = new URL(value, location.href);
    const parameterNames = [...url.searchParams.keys()];
    url.search = "";
    for (const name of parameterNames) url.searchParams.append(name, "[redacted]");
    // Hashes can contain client-side tokens, so retain only whether one exists.
    if (url.hash) url.hash = "#present";
    return url.href;
  } catch { return ""; }
}

function collectUrlMetadata() {
  const url = new URL(location.href);
  return {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port || null,
    pathname: url.pathname,
    queryParameterNames: [...new Set(url.searchParams.keys())],
    queryParameterCount: [...url.searchParams.keys()].length,
    hasFragment: !!url.hash,
    isHttps: url.protocol === "https:"
  };
}

function collectDocumentMetadata() {
  const meta = (name) => document.querySelector(`meta[name="${name}" i]`)?.content?.trim() || "";
  const property = (name) => document.querySelector(`meta[property="${name}" i]`)?.content?.trim() || "";
  const canonical = document.querySelector('link[rel="canonical"]')?.href || "";
  const inlineCode = Array.from(document.querySelectorAll("script:not([src])"))
    .map((script) => script.textContent || "").join("\n");
  return {
    description: meta("description"),
    robots: meta("robots"),
    generator: meta("generator"),
    viewport: meta("viewport"),
    canonicalUrl: canonical ? safeUrl(canonical) : "",
    language: document.documentElement.lang || "",
    charset: document.characterSet || "",
    openGraphTitle: property("og:title"),
    openGraphType: property("og:type"),
    sourceMapHint: /sourceMappingURL\s*=/.test(inlineCode),
    securityPolicyMetaPresent: !!document.querySelector('meta[http-equiv="content-security-policy" i]')
  };
}

function collectForms() {
  return Array.from(document.forms).slice(0, 100).map((form) => ({
    action: safeUrl(form.action || location.href),
    method: (form.method || "GET").toUpperCase(),
    encoding: form.enctype || "",
    target: form.target || "",
    fields: Array.from(form.elements).filter((element) => element.name).slice(0, 100).map((element) => ({
      name: element.name,
      type: element.type || element.tagName.toLowerCase(),
      required: !!element.required,
      autocomplete: element.autocomplete || "",
      maxLength: Number.isFinite(element.maxLength) && element.maxLength >= 0 ? element.maxLength : null,
      patternPresent: !!element.pattern,
      optionCount: element instanceof HTMLSelectElement ? element.options.length : undefined
    }))
  }));
}

function collectLinks() {
  const links = Array.from(document.querySelectorAll("a[href]"))
    .map((anchor) => safeUrl(anchor.href))
    .filter(Boolean);
  return Array.from(new Set(links)).slice(0, 300);
}

function collectScripts() {
  return Array.from(document.querySelectorAll("script[src]"))
    .map((script) => safeUrl(script.src))
    .filter(Boolean)
    .slice(0, 300);
}

function collectFrames() {
  return Array.from(document.querySelectorAll("iframe[src]"))
    .slice(0, 100)
    .map((frame) => ({
      url: safeUrl(frame.src),
      title: frame.title || "",
      sandboxed: frame.hasAttribute("sandbox"),
      allow: frame.getAttribute("allow") || ""
    }));
}

function collectTechnologyHints() {
  const html = document.documentElement;
  const hints = [];
  if (html.hasAttribute("data-reactroot") || document.querySelector("#__next, [data-reactroot]")) hints.push("React / Next.js markers");
  if (html.hasAttribute("ng-version") || document.querySelector("[ng-version]")) hints.push("Angular markers");
  if (document.querySelector("#___gatsby")) hints.push("Gatsby marker");
  if (document.querySelector("[data-v-app]")) hints.push("Vue marker");
  if (document.querySelector("[data-svelte-h]")) hints.push("Svelte marker");
  const generator = document.querySelector('meta[name="generator" i]')?.content?.trim();
  if (generator) hints.push(`Generator metadata: ${generator.slice(0, 100)}`);
  return [...new Set(hints)];
}

function collectStorageMetadata() {
  const safeKeys = (storage) => {
    try { return Object.keys(storage).map((key) => ({ key, length: (storage.getItem(key) || "").length })); }
    catch { return []; }
  };
  return {
    localStorageKeys: safeKeys(window.localStorage),
    sessionStorageKeys: safeKeys(window.sessionStorage),
    cookieCount: document.cookie ? document.cookie.split(";").length : 0
  };
}

// This reports a parameter name only. The matched query value is never stored.
function findReflectedUrlParams() {
  const bodyText = document.body?.innerHTML || "";
  const hits = [];
  for (const [key, value] of new URLSearchParams(location.search).entries()) {
    if (value && value.length >= 3 && bodyText.includes(value)) hits.push({ param: key });
  }
  return hits;
}

const SECRET_PATTERNS = [
  { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g },
  { name: "Generic API Key assignment", re: /[a-zA-Z0-9_]*api[_-]?key[a-zA-Z0-9_]*\s*[:=]\s*["'][a-zA-Z0-9\-_]{16,}["']/gi },
  { name: "JWT-looking token", re: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { name: "Private key block", re: /-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/g },
  { name: "Generic secret assignment", re: /[a-zA-Z0-9_]*secret[a-zA-Z0-9_]*\s*[:=]\s*["'][a-zA-Z0-9\-_]{12,}["']/gi }
];

function scanForExposedSecrets() {
  const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"))
    .map((script) => script.textContent || "").join("\n");
  return SECRET_PATTERNS.flatMap(({ name, re }) => {
    const matches = inlineScripts.match(re);
    return matches ? [{ pattern: name, count: matches.length }] : [];
  });
}
