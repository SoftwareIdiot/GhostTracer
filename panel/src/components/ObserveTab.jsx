import React, { useState } from "react";

export default function ObserveTab({ evidence }) {
  const [section, setSection] = useState("pages");

  if (!evidence) return <div className="empty">No evidence yet.</div>;

  const pages = Object.entries(evidence.pages || {});
  const requests = evidence.requests || [];
  const cookies = evidence.cookies || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        {["pages", "requests", "cookies"].map((s) => (
          <button key={s} className={section === s ? "primary" : ""} onClick={() => setSection(s)}>
            {s} ({s === "pages" ? pages.length : s === "requests" ? requests.length : cookies.length})
          </button>
        ))}
      </div>

      {section === "pages" && (
        pages.length === 0 ? <div className="empty">No pages observed yet. Browse the activated site.</div> :
        pages.map(([url, page]) => (
          <div className="card" key={url}>
            <h3 className="mono">{page.title || url}</h3>
            <div className="meta mono">{url}</div>
            <div style={{ display: "flex", gap: 16, marginTop: 6, flexWrap: "wrap" }}>
              <MiniList label="Forms" items={(page.forms || []).map((f) => `${f.method} ${f.action} [${f.fields.map((fl) => fl.name).join(", ")}]`)} />
              <MiniList label="Scripts" items={page.scripts || []} />
              <MiniList label="Links" items={(page.links || []).slice(0, 20)} />
            </div>
          </div>
        ))
      )}

      {section === "requests" && (
        requests.length === 0 ? <div className="empty">No requests captured yet.</div> :
        <table className="simple">
          <thead><tr><th>Method</th><th>URL</th><th>Type</th><th>Status</th></tr></thead>
          <tbody>
            {requests.slice().reverse().map((r) => (
              <tr key={r.id}>
                <td>{r.method}</td>
                <td className="mono" style={{ wordBreak: "break-all" }}>{r.url}</td>
                <td>{r.type}</td>
                <td>{r.status ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {section === "cookies" && (
        cookies.length === 0 ? <div className="empty">No cookies found for this origin.</div> :
        <table className="simple">
          <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Session</th></tr></thead>
          <tbody>
            {cookies.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.name}</td>
                <td>{String(c.secure)}</td>
                <td>{String(c.httpOnly)}</td>
                <td>{c.sameSite}</td>
                <td>{String(c.session)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function MiniList({ label, items }) {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ minWidth: 200 }}>
      <div className="meta">{label} ({items.length})</div>
      <pre className="evidence">{items.slice(0, 10).join("\n")}</pre>
    </div>
  );
}
