import React, { useEffect, useState, useCallback, useRef, lazy, Suspense } from "react";
import { getInspectedOrigin, api, subscribeToUpdates } from "./lib/messaging.js";
import { runDetection } from "./lib/detectionEngine.js";

import ObserveTab from "./components/ObserveTab.jsx";
import FindingsTab from "./components/FindingsTab.jsx";
import VerifyTab from "./components/VerifyTab.jsx";
import ReportTab from "./components/ReportTab.jsx";

const TABS = ["Observe", "Map", "Findings", "Verify", "Report"];
const MapGraph = lazy(() => import("./components/MapGraph.jsx"));

export default function App() {
  const [origin, setOrigin] = useState(null);
  const [active, setActive] = useState(false);
  const [evidence, setEvidence] = useState(null);
  const [cookies, setCookies] = useState([]);
  const [workspace, setWorkspace] = useState({ reviews: {}, manualFindings: [], notes: "" });
  const workspaceRef = useRef(workspace);
  const [tab, setTab] = useState("Observe");

  const refresh = useCallback(async (o) => {
    const theOrigin = o || origin;
    if (!theOrigin) return;
    const [state, ev, cks, ws] = await Promise.all([
      api.getState(theOrigin),
      api.getEvidence(theOrigin),
      api.getCookies(theOrigin),
      api.getWorkspace(theOrigin)
    ]);
    setActive(!!state?.active);
    setEvidence(ev);
    setCookies(Array.isArray(cks) ? cks : []);
    const nextWorkspace = ws || { reviews: {}, manualFindings: [], notes: "" };
    workspaceRef.current = nextWorkspace;
    setWorkspace(nextWorkspace);
  }, [origin]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const o = await getInspectedOrigin();
      if (cancelled) return;
      setOrigin(o);
      if (o) refresh(o);
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!origin) return;
    const unsubscribe = subscribeToUpdates((msg) => {
      if (msg.type === "GT_EVIDENCE_UPDATED" && msg.origin === origin) refresh(msg.origin);
    });
    return unsubscribe;
  }, [origin, refresh]);

  // Poll gently as a fallback (ports can be unreliable across panel reloads).
  useEffect(() => {
    if (!origin) return;
    const id = setInterval(() => refresh(origin), 4000);
    return () => clearInterval(id);
  }, [origin, refresh]);

  const toggleActive = async () => {
    if (!origin) return;
    const nextActive = !active;
    await api.setActive(origin, nextActive);
    setActive(nextActive);
  };

  const clearEvidence = async () => {
    if (!origin) return;
    await api.clearEvidence(origin);
    refresh(origin);
  };

  const updateWorkspace = useCallback((patch) => {
    const next = { ...workspaceRef.current, ...patch };
    workspaceRef.current = next;
    setWorkspace(next);
    api.updateWorkspace(origin, patch);
  }, [origin]);

  const updateReview = useCallback((findingId, patch) => {
    const reviews = { ...(workspaceRef.current.reviews || {}), [findingId]: { ...(workspaceRef.current.reviews?.[findingId] || {}), ...patch } };
    updateWorkspace({ reviews });
  }, [updateWorkspace]);

  const evidenceWithCookies = evidence ? { ...evidence, cookies, workspaceNotes: workspace.notes || "" } : null;
  const detectedFindings = evidenceWithCookies ? runDetection(evidenceWithCookies) : [];
  const findings = [...detectedFindings, ...(evidence?.scanFindings || []), ...(workspace.manualFindings || [])].map((finding) => ({
    ...finding,
    review: workspace.reviews?.[finding.id] || {},
    severity: workspace.reviews?.[finding.id]?.severity || finding.severity,
    status: workspace.reviews?.[finding.id]?.status || "open",
    testerNote: workspace.reviews?.[finding.id]?.note || ""
  }));

  if (!origin) {
    return (
      <div className="app">
        <div className="empty">
          Open this panel on an http(s) page to begin.
        </div>
      </div>
      
    );
  }

  return (
    <div className="app">
      <div className="topbar">
        <span className="title">GhostTrace</span>
        <span className="origin">{origin}</span>
        <span className={`badge ${active ? "on" : "off"}`}>
          {active ? "Observation active" : "Observation inactive"}
        </span>
        <div className="spacer" />
        <button onClick={toggleActive} className={active ? "danger" : "primary"}>
          {active ? "Deactivate" : "Activate"}
        </button>
        <button onClick={clearEvidence}>Clear evidence</button>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <div key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t}
          </div>
        ))}
      </div>

      <div className="content">
        {!active && (
          <div className="disclaimer">
            Observation is inactive on this origin. Activate it (top right) only on applications
            you are explicitly authorized to test. Passive collection begins on this open page.
          </div>
        )}
        {active && <div className="disclaimer">Passive checks update automatically as pages and requests are observed. URL values and credential values are redacted from stored evidence; use the Verify tab only for a deliberate, scoped check.</div>}
        {tab === "Observe" && <ObserveTab evidence={evidenceWithCookies} />}
        {tab === "Map" && <Suspense fallback={<div className="empty">Loading the attack-surface map…</div>}><MapGraph evidence={evidenceWithCookies} findings={findings} /></Suspense>}
        {tab === "Findings" && <FindingsTab findings={[...detectedFindings, ...(evidence?.scanFindings || [])]} workspace={workspace} onReviewChange={updateReview} onWorkspaceChange={updateWorkspace} />}
        {tab === "Verify" && (
          <VerifyTab origin={origin} findings={findings} evidence={evidenceWithCookies} onRan={() => refresh(origin)} />
        )}
        {tab === "Report" && <ReportTab origin={origin} findings={findings} evidence={evidenceWithCookies} />}
      </div>
    </div>
  );
}
