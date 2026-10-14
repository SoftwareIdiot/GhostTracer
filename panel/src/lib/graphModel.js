// Builds the evidence-linked attack-surface graph described in the project
// brief: Page --generated--> Request --contains--> Finding
//        --requires verification of--> Test --test result--> Outcome
//
// Node kinds carry a `kind` used for styling: page | request | finding | verify
// Edge labels are kept short and reused consistently so the graph reads the
// same way across the whole app, matching the brief's examples.

export function buildGraphElements(evidence, findings) {
  const nodes = [];
  const edges = [];
  const addedRequestIds = new Set();

  function pageNodeId(url) {
    return "page:" + url;
  }
  function requestNodeId(req) {
    return "req:" + req.id;
  }
  function findingNodeId(f) {
    return "find:" + f.id;
  }
  function verifyNodeId(v) {
    return "verify:" + v.id;
  }

  // Page nodes
  for (const [url, page] of Object.entries(evidence.pages || {})) {
    nodes.push({
      data: { id: pageNodeId(url), kind: "page", label: shortLabel(page.title || url, url) }
    });
  }

  // Request nodes + "generated" edges from the page that was active when captured.
  // We approximate "which page generated this request" by matching origin+time
  // proximity to a page snapshot, since webRequest doesn't give us the
  // initiating document URL directly for all request types.
  const pageUrls = Object.keys(evidence.pages || {});
  for (const req of evidence.requests || []) {
    if (addedRequestIds.has(req.id)) continue;
    addedRequestIds.add(req.id);
    nodes.push({
      data: {
        id: requestNodeId(req),
        kind: "request",
        label: `${req.method} ${safePath(req.url)}`,
        status: req.status
      }
    });

    const generator = pageUrls.find((u) => new URL(u).origin === req.origin) || pageUrls[0];
    if (generator) {
      edges.push({ data: { source: pageNodeId(generator), target: requestNodeId(req), label: "generated" } });
    }
  }

  // Finding nodes + "contains" edges from the request/page they were derived from.
  for (const f of findings) {
    nodes.push({
      data: {
        id: findingNodeId(f),
        kind: "finding",
        label: f.title,
        severity: f.severity,
        confidence: f.confidence
      }
    });

    const matchingReq = (evidence.requests || []).find((r) => r.url === f.affected);
    const matchingPage = pageUrls.find((u) => u === f.affected);
    if (matchingReq) {
      edges.push({ data: { source: requestNodeId(matchingReq), target: findingNodeId(f), label: "contains" } });
    } else if (matchingPage) {
      edges.push({ data: { source: pageNodeId(matchingPage), target: findingNodeId(f), label: "contains" } });
    }
  }

  // Verify-result nodes + "requires verification of" / "test result" edges.
  for (const v of evidence.verifyResults || []) {
    nodes.push({
      data: {
        id: verifyNodeId(v),
        kind: "verify",
        label: verifyLabel(v),
        outcome: v.ok ? (v.reflected || v.redirectsToTestDomain || v.likelyAccessible ? "positive" : "negative") : "error"
      }
    });

    const relatedFinding = findings.find(
      (f) => f.suggestedVerify && f.suggestedVerify.type === v.testType && f.affected === v.targetUrl
    );
    if (relatedFinding) {
      edges.push({
        data: { source: findingNodeId(relatedFinding), target: verifyNodeId(v), label: "requires verification of" }
      });
    }
  }

  return { nodes, edges };
}

function verifyLabel(v) {
  switch (v.testType) {
    case "reflected-input": return v.reflected ? "Reflected — confirm context" : "Not reflected";
    case "open-redirect": return v.redirectsToTestDomain ? "Open redirect confirmed" : "No redirect observed";
    case "idor-object-auth": return v.likelyAccessible ? "Possible IDOR" : "Access appears restricted";
    case "security-header-behavior": return v.missing?.length ? `Missing: ${v.missing.join(", ")}` : "Headers present";
    default: return v.testType;
  }
}

function shortLabel(title, url) {
  if (title && title.trim()) return title.length > 40 ? title.slice(0, 37) + "…" : title;
  try {
    return new URL(url).pathname || "/";
  } catch {
    return url;
  }
}

function safePath(url) {
  try {
    const u = new URL(url);
    return (u.pathname || "/") + (u.search ? u.search.slice(0, 24) : "");
  } catch {
    return url;
  }
}
