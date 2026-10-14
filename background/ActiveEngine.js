// Explicit, bounded query-reflection scan. This uses a harmless text marker;
// it does not submit forms, execute script, or attempt SQL/path payloads.
const MAX_INPUTS = 10;
const REQUEST_GAP_MS = 500;
const REQUEST_TIMEOUT_MS = 8000;
const MAX_BODY_CHARS = 1024 * 1024;
const SENSITIVE_PARAM = /(?:pass(?:word)?|secret|token|auth|session|csrf|xsrf|api[_-]?key|signature|^code$)/i;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function redactUrl(value) {
  const url = new URL(value);
  for (const key of url.searchParams.keys()) url.searchParams.set(key, "[redacted]");
  return url.href;
}

async function fingerprint(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = performance.now();
  try {
    const response = await fetch(url, {
      method: "GET",
      credentials: "include",
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal
    });
    const reader = response.body?.getReader();
    let body = "";
    if (reader) {
      const decoder = new TextDecoder();
      while (body.length < MAX_BODY_CHARS) {
        const { done, value } = await reader.read();
        if (done) break;
        body += decoder.decode(value, { stream: true });
      }
      if (body.length >= MAX_BODY_CHARS) await reader.cancel();
      body += decoder.decode();
    }
    return {
      status: response.status,
      length: body.length,
      durationMs: Math.round(performance.now() - started),
      body: body.slice(0, MAX_BODY_CHARS),
      truncated: body.length >= MAX_BODY_CHARS
    };
  } catch (error) {
    return { error: String(error), durationMs: Math.round(performance.now() - started), body: "", length: 0 };
  } finally {
    clearTimeout(timeout);
  }
}

export async function runScan(inputs, onProgress = () => {}) {
  const candidates = [];
  const seen = new Set();
  for (const input of Array.isArray(inputs) ? inputs : []) {
    if (input?.method && input.method.toUpperCase() !== "GET") continue;
    if (input?.type && input.type !== "query") continue;
    try {
      const url = new URL(input.url);
      const param = String(input.param || "");
      if (!/^https?:$/.test(url.protocol) || !url.searchParams.has(param)) continue;
      if ([...url.searchParams.keys()].some((key) => SENSITIVE_PARAM.test(key))) continue;
      const key = `${url.origin}${url.pathname}${url.search}|${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ url, param });
      if (candidates.length >= MAX_INPUTS) break;
    } catch { /* ignore malformed scan inputs */ }
  }

  const findings = [];
  const total = candidates.length;
  if (total === 0) {
    throw new Error("No eligible query parameters were found. Sensitive-looking parameter URLs are excluded from scanning.");
  }
  for (let index = 0; index < total; index += 1) {
    const { url, param } = candidates[index];
    const targetUrl = redactUrl(url.href);
    onProgress({ completed: index * 3, total: total * 3, parameter: param, phase: "baseline" });
    const baseline = await fingerprint(url.href);
    if (baseline.error) throw new Error(`Baseline request failed for parameter "${param}": ${baseline.error}`);
    await sleep(REQUEST_GAP_MS);

    const marker = `gt-marker-${crypto.randomUUID()}`;
    const probeUrl = new URL(url.href);
    probeUrl.searchParams.set(param, marker);
    onProgress({ completed: index * 3 + 1, total: total * 3, parameter: param, phase: "marker" });
    const probe = await fingerprint(probeUrl.href);
    if (probe.error) throw new Error(`Marker request failed for parameter "${param}": ${probe.error}`);
    await sleep(REQUEST_GAP_MS);

    const retestUrl = new URL(url.href);
    retestUrl.searchParams.set(param, marker);
    onProgress({ completed: index * 3 + 2, total: total * 3, parameter: param, phase: "retest" });
    const retest = await fingerprint(retestUrl.href);
    if (retest.error) throw new Error(`Re-test request failed for parameter "${param}": ${retest.error}`);
    const reflected = probe.body.includes(marker);
    const repeated = retest.body.includes(marker);

    if (!baseline.error && !probe.error && reflected && repeated) {
      findings.push({
        id: `scan-${crypto.randomUUID()}`,
        title: `Reflected input candidate: ${param}`,
        category: "Reflected input",
        severity: "info",
        confidence: "candidate",
        affected: targetUrl,
        evidence: [
          `A harmless marker was returned in two responses for query parameter "${param}".`,
          `Baseline HTTP ${baseline.status}; marker HTTP ${probe.status}; repeat HTTP ${retest.status}.`,
          `Response length delta: ${probe.length - baseline.length} characters; response timing: ${baseline.durationMs} ms baseline, ${probe.durationMs} ms marker.`,
          "Reflection alone does not confirm XSS; review the output context and encoding."
        ],
        impact: "User controlled input is reflected in the response. Impact depends on the output context and whether it is safely encoded.",
        recommendation: "Apply context-aware output encoding and validate input where appropriate.",
        source: "active-scan",
        createdAt: Date.now()
      });
    }

    onProgress({ completed: index * 3 + 3, total: total * 3, parameter: param, phase: "complete" });
  }
  return findings;
}
