import React, { useCallback, useEffect, useMemo, useState } from "react";
import { runDetection } from "../../panel/src/lib/detectionEngine.js";
import { generateJsonReport, generateMarkdownReport, downloadText } from "../../panel/src/lib/reportGenerator.js";
import { dashboardApi, rememberedExtensionId, rememberExtensionId } from "./bridge.js";

const REVIEW_STATES = ["open", "investigating", "confirmed", "false positive", "accepted risk", "fixed"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function Dashboard() {
  const [extensionId, setExtensionId] = useState(rememberedExtensionId());
  const [connectInput, setConnectInput] = useState(rememberedExtensionId());
  const [connected, setConnected] = useState(false);
  const [extensionVersion, setExtensionVersion] = useState("");
  const [sites, setSites] = useState([]);
  const [selectedOrigin, setSelectedOrigin] = useState("");
  const [siteData, setSiteData] = useState(null);
  const [view, setView] = useState("findings");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [draft, setDraft] = useState(emptyDraft());
  const [theme, setTheme] = useState(() => localStorage.getItem("ghosttrace.theme") || "light");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("ghosttrace.theme", theme);
  }, [theme]);

  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");

  const loadSites = useCallback(async (id = extensionId) => {
    if (!id) return;
    const [health, result] = await Promise.all([dashboardApi.ping(id), dashboardApi.listSites(id)]);
    rememberExtensionId(id);
    setExtensionId(id);
    setConnectInput(id);
    setExtensionVersion(health.version || "");
    setSites(result.sites || []);
    setConnected(true);
    setError("");
    setSelectedOrigin((current) => current || result.sites?.[0]?.origin || "");
  }, [extensionId]);

  const connect = async (event) => {
    event?.preventDefault();
    setLoading(true);
    setError("");
    try { await loadSites(connectInput.trim()); }
    catch (err) { setConnected(false); setError(err.message || String(err)); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    const id = rememberedExtensionId();
    if (id) loadSites(id).catch((err) => { setConnected(false); setError(err.message || String(err)); });
  }, []); // initial bridge handshake only

  useEffect(() => {
    if (!connected || !extensionId) return undefined;
    const syncExtensionState = async () => {
      try {
        const result = await dashboardApi.listSites(extensionId);
        setSites(result.sites || []);
        if (selectedOrigin && result.sites?.some((site) => site.origin === selectedOrigin)) {
          const detail = await dashboardApi.getSite(extensionId, selectedOrigin);
          setSiteData((current) => ({
            ...detail.site,
            workspace: current?.origin === selectedOrigin ? current.workspace : detail.site.workspace
          }));
        }
      } catch { setConnected(false); }
    };
    const interval = window.setInterval(syncExtensionState, 8000);
    return () => window.clearInterval(interval);
  }, [connected, extensionId, selectedOrigin]);

  const loadSite = useCallback(async (origin) => {
    if (!origin || !extensionId) { setSiteData(null); return; }
    try {
      const result = await dashboardApi.getSite(extensionId, origin);
      setSiteData(result.site);
      setError("");
    } catch (err) { setError(err.message || String(err)); }
  }, [extensionId]);

  useEffect(() => { loadSite(selectedOrigin); }, [selectedOrigin, loadSite]);

  const saveWorkspace = async (patch) => {
    if (!siteData) return;
    const next = { ...siteData.workspace, ...patch };
    setSiteData({ ...siteData, workspace: next });
    try {
      const result = await dashboardApi.updateWorkspace(extensionId, siteData.origin, patch);
      setSiteData((current) => current?.origin === siteData.origin ? { ...current, workspace: result.workspace } : current);
      setSites((current) => current.map((site) => site.origin === siteData.origin ? { ...site, findingCount: (result.workspace.manualFindings || []).length } : site));
    } catch (err) { setError(`Could not save assessment: ${err.message || err}`); }
  };

  const detected = useMemo(() => siteData ? runDetection({ ...siteData.evidence, cookies: siteData.cookies }) : [], [siteData]);
  const findings = useMemo(() => [
    ...detected,
    ...(siteData?.evidence?.scanFindings || []),
    ...(siteData?.workspace?.manualFindings || [])
  ].map((finding) => {
    const review = siteData?.workspace?.reviews?.[finding.id] || {};
    return { ...finding, review, status: review.status || "open", severity: review.severity || finding.severity, testerNote: review.note || "" };
  }), [detected, siteData]);
  const openFindings = findings.filter((finding) => !["fixed", "false positive", "accepted risk"].includes(finding.status));
  const filteredSites = sites.filter((site) => `${site.origin} ${site.title}`.toLowerCase().includes(search.toLowerCase()));

  const updateReview = (id, patch) => {
    const reviews = { ...(siteData.workspace.reviews || {}), [id]: { ...(siteData.workspace.reviews?.[id] || {}), ...patch } };
    saveWorkspace({ reviews });
  };

  const addManualFinding = (event) => {
    event.preventDefault();
    const finding = {
      id: `manual-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      title: draft.title.trim(), severity: draft.severity, confidence: "tester-entered",
      category: draft.category.trim() || "Manual", affected: draft.affected.trim(),
      evidence: draft.evidence.split("\n").map((line) => line.trim()).filter(Boolean),
      impact: draft.impact.trim(), recommendation: draft.recommendation.trim(),
      reproduction: draft.reproduction.trim(), createdAt: Date.now(), source: "manual"
    };
    saveWorkspace({ manualFindings: [...(siteData.workspace.manualFindings || []), finding] });
    setDraft(emptyDraft());
    setFormOpen(false);
  };

  const removeManual = (id) => saveWorkspace({ manualFindings: (siteData.workspace.manualFindings || []).filter((finding) => finding.id !== id) });

  const toggleSite = async () => {
    if (!siteData) return;
    const active = !siteData.active;
    try {
      await dashboardApi.setActive(extensionId, siteData.origin, active);
      setSiteData({ ...siteData, active });
      setSites((current) => current.map((site) => site.origin === siteData.origin ? { ...site, active } : site));
    } catch (err) { setError(err.message || String(err)); }
  };

  const downloadReport = (format) => {
    if (!siteData || !findings.length) return;
    const evidence = { ...siteData.evidence, cookies: siteData.cookies, workspaceNotes: siteData.workspace.notes || "" };
    const text = format === "json"
      ? generateJsonReport(siteData.origin, findings, evidence)
      : generateMarkdownReport(siteData.origin, findings, evidence);
    const host = new URL(siteData.origin).hostname.replace(/[^a-z0-9.-]/gi, "_");
    downloadText(`ghosttrace-${host}.${format === "json" ? "json" : "md"}`, text, format === "json" ? "application/json" : "text/markdown");
  };

  if (!connected) return <ConnectScreen extensionId={connectInput} setExtensionId={setConnectInput} onConnect={connect} loading={loading} error={error} theme={theme} onThemeToggle={toggleTheme} />;

  const evidence = siteData?.evidence;
  const activeCount = sites.filter((site) => site.active).length;
  const totalRequests = sites.reduce((sum, site) => sum + site.requestCount, 0);

  return <div className="dashboard-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">G</div><div><strong>GhostTrace</strong><small>ASSESSMENT WORKSPACE</small></div></div>
      <button className={`side-link ${view === "overview" ? "chosen" : ""}`} onClick={() => setView("overview")}><span>◫</span> Overview</button>
      <div className="side-caption">SITES <span>{sites.length}</span></div>
      <label className="site-search"><span>⌕</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Find a site" /></label>
      <div className="site-list">{filteredSites.map((site) => <button key={site.origin} className={`site-link ${selectedOrigin === site.origin ? "chosen" : ""}`} onClick={() => { setSelectedOrigin(site.origin); setView("findings"); }}>
        <span className={`site-dot ${site.active ? "active" : ""}`} /><span className="site-link-copy"><strong>{site.title || hostOf(site.origin)}</strong><small>{hostOf(site.origin)}</small></span>
      </button>)}{sites.length === 0 && <div className="side-empty">Activate a site from the extension to add it here.</div>}</div>
      <div className="sidebar-foot"><span className="connection-dot" /> Connected to extension <b>{extensionVersion ? `v${extensionVersion}` : ""}</b></div>
    </aside>

    <main className="main-area">
      <header className="topbar"><div><span className="crumb">{view === "overview" ? "WORKSPACE" : "SITE ASSESSMENT"}</span><h1>{view === "overview" ? "Overview" : (siteData?.title || hostOf(selectedOrigin) || "Site")}</h1></div>
        <div className="topbar-right">{view !== "overview" && siteData && <div className="header-actions"><button onClick={() => loadSite(selectedOrigin)}>Refresh</button><button onClick={() => downloadReport("json")}>Export JSON</button><button className="button-primary" onClick={() => downloadReport("markdown")}>Export report</button></div>}<ThemeToggle theme={theme} onToggle={toggleTheme} /></div>
      </header>
      {error && <div className="error-banner"><span>{error}</span><button onClick={() => setError("")}>Dismiss</button></div>}

      {view === "overview" ? <section className="overview-page">
        <div className="welcome-row"><div><div className="eyebrow">YOUR LOCAL WORKSPACE</div><h2>One place for every assessment.</h2><p>GhostTrace keeps collected evidence and tester review notes together for each activated site.</p></div><button className="button-primary" onClick={() => { if (sites[0]) { setSelectedOrigin(sites[0].origin); setView("findings"); } }}>Open latest site</button></div>
        <div className="metric-grid"><Metric label="Sites tracked" value={sites.length} /><Metric label="Observation active" value={activeCount} /><Metric label="Requests captured" value={totalRequests.toLocaleString()} /><Metric label="Manual findings" value={sites.reduce((sum, site) => sum + site.findingCount, 0)} /></div>
        <div className="section-heading"><div><h2>Activated sites</h2><p>Evidence remains on this browser profile and is available while the extension is connected.</p></div><span>{sites.length} total</span></div>
        <div className="site-table">{sites.length === 0 ? <div className="blank-state"><div className="blank-icon">◎</div><h3>No sites in this workspace yet</h3><p>Open a website, choose the GhostTrace extension, and activate observation for that origin.</p></div> : sites.map((site) => <button className="site-row" key={site.origin} onClick={() => { setSelectedOrigin(site.origin); setView("findings"); }}><span className={`site-avatar ${site.active ? "live" : ""}`}>{hostOf(site.origin).slice(0, 1).toUpperCase()}</span><span className="site-row-name"><strong>{site.title || hostOf(site.origin)}</strong><small>{site.origin}</small></span><span className={`status-chip ${site.active ? "active" : "inactive"}`}>{site.active ? "Observing" : "Paused"}</span><span className="site-row-stat">{site.pageCount} pages</span><span className="site-row-stat">{site.requestCount} requests</span><span className="site-row-date">{formatDate(site.lastSeen)}</span><span className="row-arrow">›</span></button>)}</div>
        {sites.length === 0 && <div className="quick-start-grid"><div className="quick-start-card blue"><span>01</span><div><strong>Activate a site</strong><p>Open the extension on an authorized target and start observation.</p></div></div><div className="quick-start-card teal"><span>02</span><div><strong>Browse normally</strong><p>Pages, forms, and request metadata appear here as you use the site.</p></div></div><div className="quick-start-card violet"><span>03</span><div><strong>Review evidence</strong><p>Turn passive signals into documented findings with your own notes.</p></div></div></div>}<div className="privacy-note"><span>⌑</span><p><strong>Local by design.</strong> The dashboard reads site data from your GhostTrace extension. Evidence and assessment notes stay in this browser profile; nothing is sent to a GhostTrace server.</p></div>
      </section> : !siteData ? <div className="loading-state">Loading site assessment…</div> : <section className="site-page">
        <div className="site-summary"><div className="site-identity"><div className="site-avatar large">{hostOf(siteData.origin).slice(0, 1).toUpperCase()}</div><div><div className="site-url">{siteData.origin}</div><div className="site-subtitle">{Object.keys(evidence?.pages || {}).length} observed pages <i /> {evidence?.requests?.length || 0} requests <i /> last activity {formatDate(latestTimestamp(evidence))}</div></div></div><button className={siteData.active ? "button-outline" : "button-primary"} onClick={toggleSite}>{siteData.active ? "Pause observation" : "Resume observation"}</button></div>
        <div className="detail-metrics"><Metric label="Findings" value={findings.length} /><Metric label="Needs review" value={openFindings.length} /><Metric label="Verified" value={findings.filter((f) => f.status === "confirmed").length} /><Metric label="Captured requests" value={evidence?.requests?.length || 0} /></div>
        <nav className="view-tabs">{[["findings", "Findings", findings.length], ["surface", "Pages & forms", Object.keys(evidence?.pages || {}).length], ["requests", "Requests", evidence?.requests?.length || 0], ["cookies", "Cookies", siteData.cookies?.length || 0]].map(([key, label, count]) => <button key={key} className={view === key ? "selected" : ""} onClick={() => setView(key)}>{label}<span>{count}</span></button>)}</nav>

        {view === "findings" && <div className="findings-view">
          <div className="section-heading findings-heading"><div><h2>Finding register</h2><p>Passive checks refresh automatically as evidence arrives. Review signals and record your validation here.</p></div><button className="button-primary" onClick={() => setFormOpen((open) => !open)}>{formOpen ? "Close" : "+ Add finding"}</button></div>
          {formOpen && <form className="manual-form" onSubmit={addManualFinding}><div className="form-title"><div><h3>New finding</h3><p>Record the evidence and steps needed to reproduce it.</p></div><button type="button" className="icon-close" onClick={() => setFormOpen(false)}>×</button></div><div className="form-grid"><Field label="Title" wide><input required value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} placeholder="Short, specific description" /></Field><Field label="Severity"><select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>{SEVERITIES.map((item) => <option key={item}>{item}</option>)}</select></Field><Field label="Category"><input value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })} placeholder="e.g. Authorization" /></Field><Field label="Affected URL or component" wide><input value={draft.affected} onChange={(e) => setDraft({ ...draft, affected: e.target.value })} placeholder="https://example.test/api/resource" /></Field><Field label="Evidence"><textarea value={draft.evidence} onChange={(e) => setDraft({ ...draft, evidence: e.target.value })} placeholder="One evidence item per line" /></Field><Field label="Reproduction steps"><textarea value={draft.reproduction} onChange={(e) => setDraft({ ...draft, reproduction: e.target.value })} placeholder="Account, action, and observed result" /></Field><Field label="Potential impact"><textarea value={draft.impact} onChange={(e) => setDraft({ ...draft, impact: e.target.value })} /></Field><Field label="Recommended remediation"><textarea value={draft.recommendation} onChange={(e) => setDraft({ ...draft, recommendation: e.target.value })} /></Field></div><div className="form-footer"><button type="button" onClick={() => setFormOpen(false)}>Cancel</button><button className="button-primary" type="submit">Save finding</button></div></form>}
          {findings.length === 0 ? <div className="blank-state"><div className="blank-icon">⌕</div><h3>No findings captured</h3><p>Browse the activated site to collect evidence, or add a finding from your testing.</p></div> : findings.map((finding) => <FindingCard key={finding.id} finding={finding} onReview={(patch) => updateReview(finding.id, patch)} onDelete={() => removeManual(finding.id)} />)}
          <div className="notes-card"><div><h3>Assessment notes</h3><p>Scope, test accounts, exclusions, and context for this site.</p></div><textarea value={siteData.workspace.notes || ""} onChange={(e) => setSiteData({ ...siteData, workspace: { ...siteData.workspace, notes: e.target.value } })} placeholder="Add notes for this assessment…" /><button className="button-outline" onClick={() => saveWorkspace({ notes: siteData.workspace.notes || "" })}>Save notes</button></div>
        </div>}
        {view === "surface" && <SurfaceView pages={evidence?.pages || {}} />}
        {view === "requests" && <RequestsView requests={evidence?.requests || []} />}
        {view === "cookies" && <CookiesView cookies={siteData.cookies || []} />}
      </section>}
    </main>
  </div>;
}

function ConnectScreen({ extensionId, setExtensionId, onConnect, loading, error, theme, onThemeToggle }) {
  return <main className="connect-screen"><div className="connect-corner"><ThemeToggle theme={theme} onToggle={onThemeToggle} /></div><div className="connect-card"><div className="brand connect-brand"><div className="brand-mark">G</div><div><strong>GhostTrace</strong><small>ASSESSMENT WORKSPACE</small></div></div><div className="eyebrow">LOCAL COMPANION APP</div><h1>Bring your site assessments together.</h1><p>Connect this dashboard to the GhostTrace extension in this browser. Your observations and tester notes remain in the extension’s local storage.</p><form onSubmit={onConnect}><label className="field-label">Extension ID<input required value={extensionId} onChange={(event) => setExtensionId(event.target.value)} placeholder="Paste the ID from chrome://extensions" /></label><button className="button-primary full" disabled={loading}>{loading ? "Connecting…" : "Connect extension"}</button></form>{error && <div className="connect-error">{error}</div>}<div className="setup-hint"><strong>How to connect</strong><ol><li>Load or reload GhostTrace at <code>chrome://extensions</code>.</li><li>Click the GhostTrace icon and choose <em>Open assessment dashboard</em>.</li><li>If this page was opened directly, copy the extension ID from the Extensions page and paste it above.</li></ol></div><div className="local-tag">⌑ &nbsp;Local connection · No account or cloud sync</div></div></main>;
}

function ThemeToggle({ theme, onToggle }) {
  const next = theme === "dark" ? "light" : "dark";
  return <button className="theme-toggle" type="button" onClick={onToggle} aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`}><span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span><span>{theme === "dark" ? "Light" : "Dark"}</span></button>;
}
function FindingCard({ finding, onReview, onDelete }) {
  const [note, setNote] = useState(finding.testerNote || "");
  useEffect(() => setNote(finding.testerNote || ""), [finding.testerNote]);
  return <article className="finding-card"><div className="finding-body"><div className="finding-title"><h3>{finding.title}</h3><span className={`severity ${finding.severity}`}>{finding.severity}</span></div><div className="finding-tags"><span>{finding.category}</span><span className={finding.confidence === "observed" ? "observed" : "heuristic"}>{finding.confidence}</span><span>{finding.source === "manual" ? "Tester entered" : "Passive check"}</span></div>{finding.affected && <div className="affected-url">{finding.affected}</div>}{finding.evidence?.length > 0 && <div className="finding-detail"><strong>Evidence</strong><ul>{finding.evidence.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}{finding.impact && <p className="finding-paragraph"><strong>Impact</strong>{finding.impact}</p>}{finding.recommendation && <p className="finding-paragraph"><strong>Remediation</strong>{finding.recommendation}</p>}{finding.reproduction && <p className="finding-paragraph"><strong>Reproduction</strong>{finding.reproduction}</p>}</div><aside className="review-controls"><Field label="Review status"><select value={finding.status} onChange={(e) => onReview({ status: e.target.value })}>{REVIEW_STATES.map((state) => <option key={state}>{state}</option>)}</select></Field><Field label="Severity"><select value={finding.severity} onChange={(e) => onReview({ severity: e.target.value })}>{SEVERITIES.map((severity) => <option key={severity}>{severity}</option>)}</select></Field><Field label="Tester notes"><textarea value={note} onChange={(e) => setNote(e.target.value)} onBlur={() => { if (note !== finding.testerNote) onReview({ note }); }} placeholder="Validation notes, remaining questions…" /></Field>{finding.source === "manual" && <button className="delete-link" onClick={onDelete}>Delete manual finding</button>}</aside></article>;
}

function SurfaceView({ pages }) {
  const rows = Object.entries(pages);
  return <div className="data-view">
    {rows.length === 0 ? <Blank text="No pages observed yet. Browse the activated site, then refresh this view." /> : rows.map(([url, page]) => <article className="page-card" key={url}>
      <div className="page-card-head"><div><h3>{page.title || hostOf(url)}</h3><a href={url} target="_blank" rel="noreferrer">{url}</a></div><span>{(page.forms || []).length} forms</span></div>
      <MetadataGrid title="URL details" values={page.urlMetadata || {}} />
      <MetadataGrid title="Page metadata" values={page.documentMetadata || {}} />
      {page.technologyHints?.length > 0 && <div className="surface-section"><strong>Technology hints</strong><ul className="url-list">{page.technologyHints.map((hint) => <li key={hint}>{hint}</li>)}</ul></div>}
      {page.forms?.length > 0 && <div className="surface-section"><strong>Forms</strong>{page.forms.map((form, i) => <div className="form-observed detailed-form" key={i}><code>{form.method} {form.action}</code><span>Encoding: {form.encoding || "default"}{form.target ? ` · target ${form.target}` : ""}</span><div className="field-chips">{form.fields?.map((field) => <span className="field-chip" key={`${field.name}-${field.type}`}><strong>{field.name}</strong> · {field.type}{field.required ? " · required" : ""}{field.autocomplete ? ` · autocomplete ${field.autocomplete}` : ""}</span>)}</div></div>)}</div>}
      {page.frames?.length > 0 && <div className="surface-section"><strong>Frames <small>{page.frames.length}</small></strong><ul className="url-list">{page.frames.map((frame, i) => <li key={`${frame.url}-${i}`}>{frame.title || "Untitled frame"} · {frame.url}{frame.sandboxed ? " · sandboxed" : " · not sandboxed"}{frame.allow ? ` · allows ${frame.allow}` : ""}</li>)}</ul></div>}
      {(page.storageMetadata?.localStorageKeys?.length > 0 || page.storageMetadata?.sessionStorageKeys?.length > 0) && <div className="surface-section"><strong>Browser storage keys</strong><MetadataGrid title="Local storage" values={page.storageMetadata.localStorageKeys || []} /><MetadataGrid title="Session storage" values={page.storageMetadata.sessionStorageKeys || []} /><div className="meta">Cookie count visible to this page: {page.storageMetadata.cookieCount ?? "unknown"}. Values are not collected.</div></div>}
      {page.scripts?.length > 0 && <div className="surface-section"><strong>Scripts <small>{page.scripts.length}</small></strong><ul className="url-list">{page.scripts.slice(0, 20).map((script) => <li key={script}>{script}</li>)}</ul></div>}
      {page.links?.length > 0 && <div className="surface-section"><strong>Links <small>{page.links.length}</small></strong><ul className="url-list">{page.links.slice(0, 20).map((link) => <li key={link}>{link}</li>)}</ul></div>}
    </article>)}
  </div>;
}

function MetadataGrid({ title, values }) {
  const rows = Array.isArray(values)
    ? values.map((item) => [item.key, `${item.length} characters`])
    : Object.entries(values).filter(([, value]) => value !== "" && value != null && (!Array.isArray(value) || value.length));
  if (!rows.length) return null;
  return <div className="metadata-block"><strong>{title}</strong><dl>{rows.map(([key, value]) => <React.Fragment key={key}><dt>{key}</dt><dd>{Array.isArray(value) ? value.join(", ") : String(value)}</dd></React.Fragment>)}</dl></div>;
}

function RequestsView({ requests }) {
  const [expanded, setExpanded] = useState(null);
  return requests.length === 0 ? <Blank text="No requests captured yet. Browse the activated site to collect network metadata." /> : <div className="table-wrap"><table><thead><tr><th>Method</th><th>URL</th><th>Type</th><th>Status</th><th>Captured</th><th>Metadata</th></tr></thead><tbody>{requests.slice().reverse().map((request) => <React.Fragment key={request.id}><tr><td><span className={`method ${request.method?.toLowerCase()}`}>{request.method}</span></td><td className="request-url">{request.url}</td><td>{request.type}</td><td>{request.status ?? "—"}</td><td>{formatDate(request.timeStamp)}</td><td><button className="detail-toggle" onClick={() => setExpanded((current) => current === request.id ? null : request.id)}>{expanded === request.id ? "Hide" : "Details"}</button></td></tr>{expanded === request.id && <tr className="request-details-row"><td colSpan="6"><div className="request-details"><MetadataGrid title="Observed response headers" values={request.responseHeaders || {}} />{request.requestHeaders?.length > 0 && <div className="request-header-names"><strong>Request header names</strong><div>{request.requestHeaders.map((name) => <span key={name}>{name}</span>)}</div></div>}{request.requestBodyKeys?.length > 0 && <div className="request-header-names"><strong>Request body field names</strong><div>{request.requestBodyKeys.map((name) => <span key={name}>{name}</span>)}</div></div>}</div></td></tr>}</React.Fragment>)}</tbody></table></div>;
}

function CookiesView({ cookies }) {
  return cookies.length === 0 ? <Blank text="No cookie metadata is available for this site." /> : <div className="table-wrap"><table><thead><tr><th>Name</th><th>Domain</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Session</th></tr></thead><tbody>{cookies.map((cookie, index) => <tr key={`${cookie.name}-${index}`}><td className="cookie-name">{cookie.name}</td><td>{cookie.domain}</td><td>{boolLabel(cookie.secure)}</td><td>{boolLabel(cookie.httpOnly)}</td><td>{cookie.sameSite}</td><td>{boolLabel(cookie.session)}</td></tr>)}</tbody></table><p className="table-footnote">Cookie values are never shown or exported.</p></div>;
}

function Metric({ label, value }) { return <div className="metric-card"><span>{label}</span><strong>{value}</strong></div>; }
function Field({ label, wide, children }) { return <label className={`form-field ${wide ? "wide" : ""}`}><span>{label}</span>{children}</label>; }
function Blank({ text }) { return <div className="blank-state"><div className="blank-icon">⌕</div><p>{text}</p></div>; }
function emptyDraft() { return { title: "", severity: "medium", category: "Manual", affected: "", evidence: "", impact: "", recommendation: "", reproduction: "" }; }
function hostOf(origin = "") { try { return new URL(origin).host; } catch { return origin; } }
function formatDate(timestamp) { return timestamp ? new Date(timestamp).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "No activity yet"; }
function latestTimestamp(evidence) { return Math.max(evidence?.createdAt || 0, ...(evidence?.requests || []).map((request) => request.timeStamp || 0), ...(evidence?.domEvidence || []).map((item) => item.timestamp || 0)); }
function boolLabel(value) { return value ? "Yes" : "No"; }
