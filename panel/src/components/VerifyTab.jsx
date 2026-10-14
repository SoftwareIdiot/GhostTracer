import React, { useEffect, useMemo, useState } from "react";
import { api } from "../lib/messaging.js";

const SCAN_LIMIT = 10;
const SCAN_DELAY_MS = 500;

export default function VerifyTab({ origin, findings, evidence, onRan }) {
  const suggested = findings.filter((f) => f.suggestedVerify);
  const [running, setRunning] = useState(null);
  const [manualUrl, setManualUrl] = useState("");
  const [manualBaseId, setManualBaseId] = useState("");
  const [manualCandId, setManualCandId] = useState("");
  const [scanUrl, setScanUrl] = useState("");
  const [actionError, setActionError] = useState("");

  const observedPages = useMemo(() => {
    const knownPages = new Set(Object.keys(evidence?.pages || {}));
    for (const request of evidence?.requests || []) {
      if (request.type === "main_frame" && request.method === "GET") knownPages.add(request.url);
    }
    return [...knownPages].flatMap((value) => {
      try {
        const url = new URL(value);
        if (url.origin !== origin || !url.searchParams.size) return [];
        const keys = [...new Set(url.searchParams.keys())];
        const page = evidence?.pages?.[value];
        return [{ value, label: `${page?.title || url.pathname} · ${keys.join(", ")}`, keys }];
      } catch { return []; }
    }).sort((a, b) => a.label.localeCompare(b.label));
  }, [evidence, origin]);

  useEffect(() => {
    if (!observedPages.some((page) => page.value === scanUrl)) setScanUrl(observedPages[0]?.value || "");
  }, [observedPages, scanUrl]);

  const run = async (test) => {
    setRunning(JSON.stringify(test));
    setActionError("");
    try {
      const result = await api.runVerify(origin, test);
      if (result?.error) setActionError(result.error);
      else if (result?.summary && result?.ok === false) setActionError(result.summary);
      onRan?.();
      return result;
    } catch (error) {
      setActionError(error.message || String(error));
      return null;
    } finally {
      setRunning(null);
    }
  };

  const runQueryScan = () => run({ type: "reflected-query-scan", url: scanUrl });
  const results = (evidence?.verifyResults || []).slice().reverse();
  const selectedPage = observedPages.find((page) => page.value === scanUrl);

  return (
    <div>
      <div className="disclaimer">
        Verification sends real requests using this origin’s browser session. Run it only against a site you are authorized to test.
        The query scan is manual, GET-only, same-origin, and sends a harmless text marker. It does not submit forms or store response bodies.
      </div>

      <section className="card query-scan-card">
        <h3>Reflected input verification</h3>
        <p className="meta">This is an optional, manual check. Choose a previously observed page; GhostTrace compares a baseline with a harmless marker response for eligible query parameters, then repeats a reflection once.</p>
        {observedPages.length === 0 ? <div className="empty query-scan-empty">No observed page with query parameters is available. Browse an authorized page with a query string while observation is active.</div> : <>
          <div className="verify-form query-scan-controls">
            <label className="scan-page-label">Observed page
              <select value={scanUrl} onChange={(event) => setScanUrl(event.target.value)} disabled={running !== null}>
                {observedPages.map((page) => <option key={page.value} value={page.value}>{page.label}</option>)}
              </select>
            </label>
            <button className="primary" disabled={!scanUrl || running !== null} onClick={runQueryScan}>
              {running ? "Checking…" : "Check reflected input"}
            </button>
          </div>
          {selectedPage && <div className="scan-parameter-list"><strong>Parameters:</strong> {selectedPage.keys.join(", ")} <span>· up to {SCAN_LIMIT}, {SCAN_DELAY_MS} ms between requests</span></div>}
        </>}
        <div className="scan-safety-note">Names that look like credentials or anti-CSRF values are skipped. Other original query values stay unchanged in requests and are not copied into scan results. Redirecting responses are not followed. Reflection is a lead, not proof of XSS.</div>
      </section>

      {actionError && <div className="verify-error" role="alert">{actionError}</div>}

      <h3>Suggested from findings</h3>
      {suggested.length === 0 && <div className="empty">No auto-suggested verifications yet — they appear here once Findings flags a reflected parameter or redirect candidate.</div>}
      {suggested.map((f) => (
        <div className="card" key={f.id}>
          <h3>{f.title}</h3>
          <div className="meta mono">{f.affected}</div>
          <button className="primary" disabled={running !== null} onClick={() => run(f.suggestedVerify)}>
            {f.suggestedVerify.type === "reflected-input" ? "Run reflected-input test" : "Run open-redirect test"}
          </button>
        </div>
      ))}

      <h3>Manual tests</h3>
      <div className="card">
        <div className="meta">API authorization (IDOR) — compares a baseline object id against a candidate id using the current session's test account.</div>
        <div className="verify-form">
          <input placeholder="https://target/api/invoices/{id}" style={{ minWidth: 260 }} value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} />
          <input placeholder="baseline id (e.g. 1042)" value={manualBaseId} onChange={(e) => setManualBaseId(e.target.value)} />
          <input placeholder="candidate id (e.g. 1043)" value={manualCandId} onChange={(e) => setManualCandId(e.target.value)} />
          <button disabled={!manualUrl || !manualBaseId || !manualCandId || running !== null} onClick={() => run({ type: "idor-object-auth", url: manualUrl.replace("{id}", manualBaseId), baselineId: manualBaseId, candidateId: manualCandId })}>Run IDOR test</button>
        </div>
      </div>

      <div className="card">
        <div className="meta">Security configuration behavior — re-requests a URL directly and reports which security headers are actually present.</div>
        <div className="verify-form">
          <input placeholder="https://target/some/endpoint" style={{ minWidth: 300 }} value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} />
          <button disabled={!manualUrl || running !== null} onClick={() => run({ type: "security-header-behavior", url: manualUrl })}>Run header-behavior test</button>
        </div>
      </div>

      <h3>Results</h3>
      {results.length === 0 && <div className="empty">No verification tests run yet.</div>}
      {results.map((result) => <VerificationResult key={result.id} result={result} />)}
    </div>
  );
}

function VerificationResult({ result }) {
  return <div className="card verification-result">
    <h3>{result.testType} {result.ok ? "" : <span className="sev sev-high">error</span>}</h3>
    <div className="meta mono">{result.targetUrl}</div>
    <div className="verification-summary">{result.summary}</div>
    {result.baseline && <div className="meta">Baseline: HTTP {result.baseline.status}, {formatBytes(result.baseline.responseLength)}{result.baseline.truncated ? "+" : ""}, {result.baseline.durationMs} ms</div>}
    {result.excludedParameters?.length > 0 && <div className="meta">Skipped sensitive-looking parameter names: {result.excludedParameters.join(", ")}</div>}
    {result.omittedParameters?.length > 0 && <div className="meta">Parameter cap reached; not scanned: {result.omittedParameters.join(", ")}</div>}
    {result.scanItems?.map((item, index) => <div className="scan-result-item" key={`${item.parameter}-${index}`}>
      <div className="scan-result-title"><strong>?{item.parameter}</strong><span className="sev sev-info">{item.severity}</span><span className="conf">{item.confidence}</span></div>
      <div className="scan-result-line"><strong>Marker:</strong> <code>{item.payload}</code></div>
      {item.error ? <div className="meta">{item.error}</div> : <>
        <div className="scan-result-line"><strong>Baseline:</strong> HTTP {item.baseline.status}, {formatBytes(item.baseline.responseLength)}{item.baseline.truncated ? "+" : ""}, {item.baseline.durationMs} ms</div>
        <div className="scan-result-line"><strong>Marker response:</strong> HTTP {item.anomalousResponse.status}, {formatBytes(item.anomalousResponse.responseLength)}{item.anomalousResponse.truncated ? "+" : ""}, {item.anomalousResponse.durationMs} ms{item.anomalousResponse.contentType ? `, ${item.anomalousResponse.contentType}` : ""}; {item.anomalousResponse.markerReflected ? `reflected in ${item.anomalousResponse.reflectionContext}` : "marker not observed"}</div>
        {item.diff && <div className="scan-result-line"><strong>Difference:</strong> status {item.diff.statusChanged ? "changed" : "unchanged"}; body length {signed(item.diff.responseLengthDelta)} bytes; duration {signed(item.diff.durationDeltaMs)} ms{item.diff.responseTruncated ? " (body sample capped at 1 MiB)" : ""}</div>}
        {item.retest && <div className="scan-result-line"><strong>Re-test:</strong> {item.retest.payload && <><code>{item.retest.payload}</code>; </>}{item.retest.error || `HTTP ${item.retest.status}, ${formatBytes(item.retest.responseLength)}${item.retest.truncated ? "+" : ""}, ${item.retest.durationMs} ms; ${item.retest.markerReflected ? `marker repeated in ${item.retest.reflectionContext}` : "marker did not repeat"}`}</div>}
        <div className="meta">Reflection confidence describes repeatability only. XSS is not confirmed by this scan.</div>
      </>}
    </div>)}
    <div className="meta">{new Date(result.timestamp).toLocaleString()}</div>
  </div>;
}

function formatBytes(value = 0) { return `${Number(value).toLocaleString()} bytes`; }
function signed(value = 0) { return `${value > 0 ? "+" : ""}${value}`; }
