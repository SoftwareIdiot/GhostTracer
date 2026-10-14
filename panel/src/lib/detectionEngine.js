// Module 3: Detect
// Runs passive checks against evidence already collected by Module 1.
// Nothing here makes a new network request — see verify tests (Module 4)
// for anything active.
//
// Every finding carries a `confidence`:
//   "observed"  — directly read from captured data (header present/absent,
//                 cookie flag, literal regex match in page source)
//   "heuristic" — a pattern-based warning that needs human/Module-4 review

const SECURITY_HEADERS = [
  { key: "content-security-policy", title: "Content-Security-Policy", why: "Mitigates XSS and data-injection by restricting allowed sources." },
  { key: "x-frame-options", title: "X-Frame-Options", why: "Mitigates clickjacking via iframe embedding." },
  { key: "strict-transport-security", title: "Strict-Transport-Security", why: "Forces HTTPS, mitigating downgrade/MITM attacks." },
  { key: "x-content-type-options", title: "X-Content-Type-Options", why: "Prevents MIME-sniffing based attacks." },
  { key: "referrer-policy", title: "Referrer-Policy", why: "Controls leakage of sensitive URL data via the Referer header." }
];

const SENSITIVE_FIELD_NAMES = [
  "password", "passwd", "secret", "token", "api_key", "apikey", "ssn",
  "credit_card", "card_number", "cvv", "private_key", "access_token", "refresh_token"
];

const REDIRECT_PARAM_NAMES = ["redirect", "redirect_uri", "return", "returnurl", "next", "url", "dest", "destination", "continue"];

function makeFinding(f) {
  // Findings are regenerated whenever new evidence arrives. A content-derived id
  // keeps saved triage notes attached to the same observation across refreshes.
  const stableEvidence = (f.evidence || []).map((item) =>
    String(item).replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/g, "<timestamp>")
  );
  const identity = [f.category, f.title, f.affected, ...stableEvidence].join("|");
  let hash = 2166136261;
  for (let i = 0; i < identity.length; i += 1) {
    hash ^= identity.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return { id: `f-${(hash >>> 0).toString(36)}`, ...f };
}

export function runDetection(evidence) {
  const findings = [];

  findings.push(...detectSecurityHeaders(evidence));
  findings.push(...detectCookieIssues(evidence));
  findings.push(...detectExposedSecrets(evidence));
  findings.push(...detectSensitiveApiFields(evidence));
  findings.push(...detectOpenRedirectCandidates(evidence));
  findings.push(...detectDomXssCandidates(evidence));
  findings.push(...detectVulnerableDependencies(evidence));
  findings.push(...detectInsecureFormActions(evidence));
  findings.push(...detectMixedContent(evidence));
  findings.push(...detectSourceMapHints(evidence));

  return [...new Map(findings.map((finding) => [finding.id, finding])).values()];
}

function detectSecurityHeaders(evidence) {
  const findings = [];
  // Look at the most recent document-type response per distinct URL path.
  const docRequests = evidence.requests.filter((r) => r.type === "main_frame" && r.responseHeaders);
  const latestByUrl = new Map();
  for (const r of docRequests) latestByUrl.set(r.url, r);

  for (const r of latestByUrl.values()) {
    const url = new URL(r.url);
    const headers = r.responseHeaders;
    const hasFrameAncestors = /(?:^|;)\s*frame-ancestors\b/i.test(headers["content-security-policy"] || "");
    const applicable = SECURITY_HEADERS.filter((h) => {
      if (h.key === "strict-transport-security" && url.protocol !== "https:") return false;
      if (h.key === "x-frame-options" && hasFrameAncestors) return false;
      return true;
    });
    const missing = applicable.filter((h) => !headers[h.key]);
    if (missing.length === 0) continue;
    const headerNames = missing.map((m) => m.title);
    const status = r.status ? `HTTP ${r.status}` : "response status unavailable";
    findings.push(
      makeFinding({
        title: `${headerNames.length} security header${headerNames.length === 1 ? "" : "s"} absent on ${url.pathname || "/"}`,
        category: "Security Headers",
        severity: missing.some((h) => h.key === "content-security-policy") ? "medium" : "low",
        confidence: "observed",
        affected: r.url,
        evidence: [`Observed ${r.method || "GET"} ${url.pathname || "/"} (${status})${r.timeStamp ? ` at ${new Date(r.timeStamp).toISOString()}` : ""}.`, ...missing.map((m) => `${m.title} was absent. ${m.why}`)],
        impact: "These are defense-in-depth controls. Their absence alone does not establish an exploitable vulnerability; impact depends on the page behavior and threat model.",
        recommendation: `Review whether these controls apply to this response, then configure: ${headerNames.join(", ")}. A Content-Security-Policy frame-ancestors directive can replace X-Frame-Options in modern browsers.`
      })
    );
  }
  return findings;
}

function detectCookieIssues(evidence) {
  const findings = [];
  const cookies = evidence.cookies || [];
  for (const c of cookies) {
    const issues = [];
    const name = (c.name || "").toLowerCase();
    const likelySession = /(?:session|sess|auth|token|jwt|sid|login|identity)/i.test(name);
    if (!c.secure && evidence.origin?.startsWith("https:")) issues.push("missing Secure flag on an HTTPS site");
    if (!c.httpOnly && likelySession) issues.push("session-like cookie lacks HttpOnly");
    if ((!c.sameSite || c.sameSite === "no_restriction") && likelySession) issues.push("session-like cookie has no effective SameSite restriction");
    if (issues.length === 0) continue;
    const sensitiveConcern = likelySession;
    findings.push(
      makeFinding({
        title: `Insecure cookie configuration: "${c.name}"`,
        category: "Cookie Security",
        severity: sensitiveConcern && (!c.httpOnly || !c.secure || !c.sameSite || c.sameSite === "no_restriction") ? "medium" : "low",
        confidence: "observed",
        affected: `${c.domain}${c.path}`,
        evidence: [`Cookie "${c.name}" on ${c.domain}${c.path || "/"}: ${issues.join(", ")}.`, `Observed flags: Secure=${!!c.secure}, HttpOnly=${!!c.httpOnly}, SameSite=${c.sameSite || "unspecified"}, session=${!!c.session}.`],
        impact: !c.httpOnly && likelySession
          ? "JavaScript can read a cookie without HttpOnly. That increases impact if a script-injection flaw is independently confirmed; this observation alone does not prove session exposure."
          : "This cookie configuration may weaken transport or cross-site protections. Confirm the cookie's purpose and whether it contains sensitive state before assigning impact.",
        recommendation: "For authentication/session cookies, use Secure over HTTPS, HttpOnly where JavaScript access is unnecessary, and an intentional SameSite policy. Do not apply these flags blindly to cookies that require client-side access."
      })
    );
  }
  return findings;
}

function detectExposedSecrets(evidence) {
  const findings = [];
  for (const dom of evidence.domEvidence) {
    for (const s of dom.secretsCandidates || []) {
      findings.push(
        makeFinding({
          title: `Possible exposed secret in page source: ${s.pattern}`,
          category: "Information Exposure",
          severity: "high",
          confidence: "heuristic",
          affected: dom.url,
          evidence: [`Pattern "${s.pattern}" matched ${s.count} time(s) in inline script content. Secret samples are not retained.`],
          impact: "If confirmed real, an exposed key/secret/token may allow impersonation, data access, or lateral movement depending on its scope.",
          recommendation: "Move secrets server-side, rotate any credential confirmed to be real, and verify the match is not a false positive (test fixture, placeholder, etc.)."
        })
      );
    }
  }
  return findings;
}

function detectInsecureFormActions(evidence) {
  if (!evidence.origin?.startsWith("https:")) return [];
  const findings = [];
  for (const dom of evidence.domEvidence || []) {
    for (const form of dom.forms || []) {
      try {
        const action = new URL(form.action || dom.url, dom.url);
        if (action.protocol !== "http:") continue;
        findings.push(makeFinding({
          title: "Form submits to an insecure HTTP destination",
          category: "Transport Security",
          severity: "high",
          confidence: "observed",
          affected: form.action || dom.url,
          evidence: [`A form on an HTTPS page uses ${action.origin}${action.pathname} as its action.`, `Observed method: ${form.method || "GET"}; field names only: ${(form.fields || []).map((field) => field.name).filter(Boolean).join(", ") || "none"}.`],
          impact: "Form contents may be exposed or modified in transit after leaving the HTTPS page.",
          recommendation: "Submit sensitive forms only to HTTPS endpoints and confirm every redirect stays on HTTPS."
        }));
      } catch { /* ignore malformed form actions */ }
    }
  }
  return findings;
}

function detectMixedContent(evidence) {
  if (!evidence.origin?.startsWith("https:")) return [];
  const findings = [];
  for (const dom of evidence.domEvidence || []) {
    for (const resource of [...(dom.scripts || []), ...(dom.frames || []).map((frame) => frame.url)]) {
      try {
        const url = new URL(resource, dom.url);
        if (url.protocol !== "http:") continue;
        findings.push(makeFinding({
          title: `Insecure HTTP resource on HTTPS page: ${url.hostname}`,
          category: "Mixed Content",
          severity: "medium",
          confidence: "observed",
          affected: url.href,
          evidence: [`The HTTPS page referenced an HTTP ${dom.scripts?.includes(resource) ? "script" : "frame"} resource.`],
          impact: "An unencrypted resource can be modified in transit and may undermine the security of the HTTPS page.",
          recommendation: "Serve active page resources over HTTPS and remove insecure resource references."
        }));
      } catch { /* ignore malformed resource URLs */ }
    }
  }
  return findings;
}

function detectSourceMapHints(evidence) {
  const findings = [];
  for (const dom of evidence.domEvidence || []) {
    if (!dom.documentMetadata?.sourceMapHint) continue;
    findings.push(makeFinding({
      title: "Inline script advertises a source map",
      category: "Source Exposure",
      severity: "info",
      confidence: "observed",
      affected: dom.url,
      evidence: ["An inline script contains a sourceMappingURL directive. The source map itself was not fetched."],
      impact: "A publicly available source map may reveal original source structure and comments; its presence alone is not a vulnerability.",
      recommendation: "Check whether the referenced map is intended to be public and ensure no secrets are embedded in source or build metadata."
    }));
  }
  return findings;
}

function detectSensitiveApiFields(evidence) {
  const findings = [];
  for (const r of evidence.requests) {
    const keys = r.requestBodyKeys || [];
    const hits = keys.filter((k) => SENSITIVE_FIELD_NAMES.some((s) => k.toLowerCase().includes(s)));
    if (hits.length === 0) continue;
    findings.push(
      makeFinding({
        title: `Sensitive-looking field(s) submitted to ${new URL(r.url).pathname}`,
        category: "Sensitive Data Handling",
        severity: "low",
        confidence: "heuristic",
        affected: r.url,
        evidence: [`Request body field names included: ${hits.join(", ")}`],
        impact: "Field names alone don't confirm exposure, but indicate where to focus manual review (transport security, logging, response echoing).",
        recommendation: "Confirm these fields are transmitted over TLS, not logged in plaintext, and not echoed back unnecessarily in responses."
      })
    );
  }
  return findings;
}

function detectOpenRedirectCandidates(evidence) {
  const findings = [];
  const seen = new Set();
  for (const r of evidence.requests) {
    let u;
    try { u = new URL(r.url); } catch { continue; }
    for (const name of REDIRECT_PARAM_NAMES) {
      if (u.searchParams.has(name) && !seen.has(u.origin + u.pathname + name)) {
        seen.add(u.origin + u.pathname + name);
        findings.push(
          makeFinding({
            title: `Potential open-redirect parameter: "${name}" on ${u.pathname}`,
            category: "Redirect Handling",
            severity: "low",
            confidence: "heuristic",
            affected: r.url,
            evidence: [`Observed query parameter "${name}" used on this endpoint.`],
            impact: "If the server redirects to this parameter's value without validation, it can be used for phishing or OAuth token theft.",
            recommendation: "Use Module 4 → Open Redirect verification to confirm, then allow-list redirect destinations server-side.",
            suggestedVerify: { type: "open-redirect", url: r.url, param: name }
          })
        );
      }
    }
  }
  return findings;
}

function detectDomXssCandidates(evidence) {
  const findings = [];
  for (const dom of evidence.domEvidence) {
    for (const hit of dom.reflectedParams || []) {
      findings.push(
        makeFinding({
          title: `URL parameter "${hit.param}" appears in rendered page content`,
          category: "Client-Side Data Flow",
          severity: "medium",
          confidence: "heuristic",
          affected: dom.url,
          evidence: [`The current URL parameter name "${hit.param}" had a value present in document.body.innerHTML. The value itself is deliberately not retained because query strings can contain sensitive data.`],
          impact: "Reflection alone does not establish script execution. Risk depends on the exact DOM sink, output context, and whether the value is safely encoded.",
          recommendation: "Use the explicit harmless-marker verification, then review the relevant rendering code and output context. Treat this as a lead until an unsafe sink is demonstrated.",
          suggestedVerify: { type: "reflected-input", url: dom.url, param: hit.param }
        })
      );
    }
  }
  return findings;
}

// Small, intentionally curated/educational list — NOT a substitute for a
// real SCA tool (e.g. retire.js, npm audit, Snyk). Flags only as heuristic.
const KNOWN_OLD_LIBS = [
  { match: /jquery[-.](1(\.[0-6])?)[\d.]*\.min\.js/i, name: "jQuery < 1.7", note: "Older jQuery releases have multiple known XSS/prototype-pollution advisories." },
  { match: /angular(\.js)?[-.]1\.[0-5]\./i, name: "AngularJS 1.0–1.5", note: "Older AngularJS 1.x releases have known sandbox-escape/XSS advisories." },
  { match: /bootstrap[-.]3\./i, name: "Bootstrap 3.x", note: "Older Bootstrap releases have known XSS advisories in certain plugins (tooltip/affix/scrollspy)." }
];

function detectVulnerableDependencies(evidence) {
  const findings = [];
  const allScripts = new Set();
  for (const dom of evidence.domEvidence) for (const s of dom.scripts || []) allScripts.add(s);

  for (const src of allScripts) {
    for (const lib of KNOWN_OLD_LIBS) {
      if (lib.match.test(src)) {
        findings.push(
          makeFinding({
            title: `Potentially outdated dependency: ${lib.name}`,
            category: "Vulnerable Dependencies",
            severity: "medium",
            confidence: "heuristic",
            affected: src,
            evidence: [`Script URL matched version pattern for ${lib.name}: ${src}`],
            impact: lib.note,
            recommendation: "Confirm the exact version and cross-check against a dedicated SCA tool / CVE database before reporting as confirmed."
          })
        );
      }
    }
  }
  return findings;
}
