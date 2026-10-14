import React, { useMemo, useState } from "react";

const STATUSES = ["open", "investigating", "confirmed", "false positive", "accepted risk", "fixed"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function FindingsTab({ findings, workspace, onReviewChange, onWorkspaceChange }) {
  const [filter, setFilter] = useState("all");
  const [showForm, setShowForm] = useState(false);
  const [draft, setDraft] = useState({ title: "", severity: "medium", category: "Manual", affected: "", evidence: "", impact: "", recommendation: "", reproduction: "" });
  const reviews = workspace?.reviews || {};
  const allFindings = useMemo(() => [...findings, ...(workspace?.manualFindings || [])], [findings, workspace?.manualFindings]);
  const visible = filter === "all" ? allFindings : allFindings.filter((f) => (reviews[f.id]?.status || "open") === filter);

  const saveManual = (event) => {
    event.preventDefault();
    const now = Date.now();
    const finding = {
      id: `manual-${now}-${Math.random().toString(36).slice(2, 7)}`,
      title: draft.title.trim(), severity: draft.severity, confidence: "tester-entered",
      category: draft.category.trim() || "Manual", affected: draft.affected.trim(),
      evidence: draft.evidence.split("\n").map((line) => line.trim()).filter(Boolean),
      impact: draft.impact.trim(), recommendation: draft.recommendation.trim(),
      reproduction: draft.reproduction.trim(), createdAt: now, source: "manual"
    };
    onWorkspaceChange({ manualFindings: [...(workspace?.manualFindings || []), finding] });
    setDraft({ title: "", severity: "medium", category: "Manual", affected: "", evidence: "", impact: "", recommendation: "", reproduction: "" });
    setShowForm(false);
  };

  const removeManual = (id) => onWorkspaceChange({ manualFindings: (workspace?.manualFindings || []).filter((f) => f.id !== id) });

  return (
    <div className="findings-workspace">
      <div className="workspace-heading">
        <div><div className="eyebrow">AUTOMATIC PASSIVE REVIEW</div><h2>Findings</h2><p>Checks refresh as new evidence arrives. Review each signal, record validation, and keep notes with this site.</p></div>
        <button className="primary" onClick={() => setShowForm((value) => !value)}>{showForm ? "Close form" : "+ Add finding"}</button>
      </div>

      <div className="finding-stats">
        <Stat label="Total" value={allFindings.length} />
        <Stat label="Open" value={allFindings.filter((f) => !reviews[f.id]?.status || reviews[f.id]?.status === "open").length} />
        <Stat label="Confirmed" value={allFindings.filter((f) => reviews[f.id]?.status === "confirmed").length} />
        <Stat label="Manual" value={(workspace?.manualFindings || []).length} />
      </div>

      {showForm && <form className="card finding-form" onSubmit={saveManual}>
        <h3>Record a finding</h3>
        <div className="form-grid">
          <label className="field wide">Title<input required value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} placeholder="e.g. Invoice endpoint exposes another account's record" /></label>
          <label className="field">Severity<select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
          <label className="field">Category<input value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })} /></label>
          <label className="field wide">Affected URL or component<input value={draft.affected} onChange={(e) => setDraft({ ...draft, affected: e.target.value })} placeholder="https://target.example/api/..." /></label>
          <label className="field">Evidence<textarea value={draft.evidence} onChange={(e) => setDraft({ ...draft, evidence: e.target.value })} placeholder="One evidence item per line" /></label>
          <label className="field">Reproduction steps<textarea value={draft.reproduction} onChange={(e) => setDraft({ ...draft, reproduction: e.target.value })} placeholder="Steps and account/context used" /></label>
          <label className="field">Potential impact<textarea value={draft.impact} onChange={(e) => setDraft({ ...draft, impact: e.target.value })} /></label>
          <label className="field">Recommended remediation<textarea value={draft.recommendation} onChange={(e) => setDraft({ ...draft, recommendation: e.target.value })} /></label>
        </div>
        <div className="form-actions"><button type="button" onClick={() => setShowForm(false)}>Cancel</button><button className="primary" type="submit">Save finding</button></div>
      </form>}

      <div className="finding-toolbar">
        <div className="filter-pills">{["all", ...STATUSES].map((s) => <button key={s} className={filter === s ? "selected" : ""} onClick={() => setFilter(s)}>{s}{s === "all" ? ` · ${allFindings.length}` : ` · ${allFindings.filter((f) => (reviews[f.id]?.status || "open") === s).length}`}</button>)}</div>
      </div>

      {visible.length === 0 ? <div className="empty">{allFindings.length ? "No findings match this status." : "No findings recorded yet. Browse the activated site to collect evidence, or add a finding from your own testing."}</div> : visible.map((f) => {
        const review = reviews[f.id] || {};
        return <article className="finding-card" key={f.id}>
          <div className="finding-card-main">
            <div className="finding-title-row"><h3>{f.title}</h3><span className={`sev sev-${review.severity || f.severity}`}>{review.severity || f.severity}</span></div>
            <div className="finding-meta"><span>{f.category}</span><span className={`conf ${f.confidence === "observed" ? "observed" : ""}`}>{f.confidence}</span><span>{f.source === "manual" ? "Tester entered" : "Passive check"}</span></div>
            {f.affected && <div className="finding-target mono">{f.affected}</div>}
            {f.evidence?.length > 0 && <div className="finding-evidence"><strong>Evidence</strong><ul>{f.evidence.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
            {f.impact && <p className="finding-copy"><strong>Impact</strong> {f.impact}</p>}
            {f.recommendation && <p className="finding-copy"><strong>Remediation</strong> {f.recommendation}</p>}
            {f.reproduction && <p className="finding-copy"><strong>Reproduction</strong> {f.reproduction}</p>}
          </div>
          <div className="finding-review">
            <label className="field">Review status<select value={review.status || "open"} onChange={(e) => onReviewChange(f.id, { status: e.target.value })}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select></label>
            <label className="field">Severity<select value={review.severity || f.severity} onChange={(e) => onReviewChange(f.id, { severity: e.target.value })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
            <label className="field">Tester notes<textarea value={review.note || ""} onChange={(e) => onReviewChange(f.id, { note: e.target.value })} placeholder="What did you verify? What remains unknown?" /></label>
            {f.source === "manual" && <button className="danger" onClick={() => removeManual(f.id)}>Delete manual finding</button>}
          </div>
        </article>;
      })}

      <section className="site-notes card">
        <div><h3>Site assessment notes</h3><p className="meta">Scope, test accounts, exclusions, and context for this origin.</p></div>
        <textarea value={workspace?.notes || ""} onChange={(e) => onWorkspaceChange({ notes: e.target.value })} placeholder="Keep general engagement notes for this site…" />
      </section>
    </div>
  );
}

function Stat({ label, value }) { return <div className="stat"><span>{label}</span><strong>{value}</strong></div>; }
