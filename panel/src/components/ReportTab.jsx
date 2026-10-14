import React, { useMemo, useState } from "react";
import { generateJsonReport, generateMarkdownReport, downloadText } from "../lib/reportGenerator.js";

export default function ReportTab({ origin, findings, evidence }) {
  const [format, setFormat] = useState("markdown");

  const text = useMemo(() => {
    if (!evidence) return "";
    return format === "markdown"
      ? generateMarkdownReport(origin, findings, evidence)
      : generateJsonReport(origin, findings, evidence);
  }, [format, origin, findings, evidence]);

  const download = () => {
    const safeHost = origin.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "_");
    const filename = `ghosttrace-report-${safeHost}.${format === "markdown" ? "md" : "json"}`;
    downloadText(filename, text, format === "markdown" ? "text/markdown" : "application/json");
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10, alignItems: "center" }}>
        <button className={format === "markdown" ? "primary" : ""} onClick={() => setFormat("markdown")}>Markdown</button>
        <button className={format === "json" ? "primary" : ""} onClick={() => setFormat("json")}>JSON</button>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="primary" onClick={download} disabled={!findings.length}>
          Download report
        </button>
      </div>
      {!findings.length ? (
        <div className="empty">No findings to report yet.</div>
      ) : (
        <pre className="evidence" style={{ maxHeight: "calc(100vh - 170px)" }}>{text}</pre>
      )}
    </div>
  );
}
