export function generateJsonReport(origin, findings, evidence) {
  return JSON.stringify(
    {
      tool: "GhostTrace",
      generatedAt: new Date().toISOString(),
      target: origin,
      summary: {
        totalFindings: findings.length,
        bySeverity: countBy(findings, "severity"),
        byConfidence: countBy(findings, "confidence")
      },
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status || "open",
        testerNote: f.testerNote || "",
        category: f.category,
        affected: f.affected,
        evidence: f.evidence,
        impact: f.impact,
        recommendation: f.recommendation,
        reproduction: f.reproduction || ""
      })),
      verifyResults: evidence.verifyResults || [],
      siteNotes: evidence.workspaceNotes || ""
    },
    null,
    2
  );
}

export function generateMarkdownReport(origin, findings, evidence) {
  const lines = [];
  lines.push(`# GhostTrace Security Report`);
  lines.push("");
  lines.push(`**Target:** ${origin}`);
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push("");
  lines.push(`## Summary`);
  lines.push("");
  lines.push(`- Total findings: ${findings.length}`);
  const bySeverity = countBy(findings, "severity");
  for (const [sev, count] of Object.entries(bySeverity)) {
    lines.push(`- ${capitalize(sev)}: ${count}`);
  }
  lines.push("");
  lines.push(`> Confidence legend: **observed** = directly read from captured evidence; **heuristic** = pattern-based warning requiring verification.`);
  lines.push("");
  lines.push(`## Findings`);

  const ordered = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  for (const f of ordered) {
    lines.push("");
    lines.push(`### ${f.title}`);
    lines.push("");
    lines.push(`| Field | Value |`);
    lines.push(`|---|---|`);
    lines.push(`| Severity | ${capitalize(f.severity)} |`);
    lines.push(`| Confidence | ${capitalize(f.confidence)} |`);
    lines.push(`| Review status | ${capitalize(f.status || "open")} |`);
    lines.push(`| Category | ${f.category} |`);
    lines.push(`| Affected | \`${f.affected || "n/a"}\` |`);
    lines.push("");
    lines.push(`**Evidence**`);
    for (const e of f.evidence || []) lines.push(`- ${e}`);
    lines.push("");
    lines.push(`**Potential impact:** ${f.impact}`);
    lines.push("");
    lines.push(`**Recommended remediation:** ${f.recommendation}`);
    if (f.reproduction) {
      lines.push("");
      lines.push(`**Reproduction steps:** ${f.reproduction}`);
    }
    if (f.testerNote) {
      lines.push("");
      lines.push(`**Tester notes:** ${f.testerNote}`);
    }

    const related = (evidence.verifyResults || []).filter(
      (v) => f.suggestedVerify && v.testType === f.suggestedVerify.type && v.targetUrl === f.affected
    );
    if (related.length) {
      lines.push("");
      lines.push(`**Verification performed**`);
      for (const v of related) {
        lines.push(`- [${new Date(v.timestamp).toISOString()}] ${v.summary}`);
      }
    }
  }

  if (evidence.workspaceNotes) {
    lines.push("");
    lines.push("## Site assessment notes");
    lines.push("");
    lines.push(evidence.workspaceNotes);
  }

  const scans = (evidence.verifyResults || []).filter((result) => result.testType === "reflected-query-scan");
  if (scans.length) {
    lines.push("");
    lines.push("## Reflected input verification log");
    lines.push("");
    lines.push("These checks use non-executable markers. Reflection is not proof of XSS; response bodies are not stored.");
    for (const scan of scans) {
      lines.push("");
      lines.push(`### Scan — ${scan.targetUrl || "observed page"}`);
      lines.push("");
      lines.push(`**Run:** ${scan.timestamp ? new Date(scan.timestamp).toISOString() : "unknown"}`);
      lines.push(`**Summary:** ${scan.summary || "n/a"}`);
      if (scan.baseline) lines.push(`**Baseline:** HTTP ${scan.baseline.status}, ${scan.baseline.responseLength}${scan.baseline.truncated ? "+" : ""} bytes, ${scan.baseline.durationMs} ms`);
      for (const item of scan.scanItems || []) {
        lines.push("");
        lines.push(`#### Query parameter: ${item.parameter}`);
        lines.push(`- Severity: ${capitalize(item.severity || "info")}`);
        lines.push(`- Reflection confidence: ${item.confidence || "n/a"} (repeatability only; XSS not confirmed)`);
        lines.push(`- Marker sent: \`${item.payload || "n/a"}\``);
        if (item.error) {
          lines.push(`- Request result: ${item.error}`);
          continue;
        }
        const baseline = item.baseline || {};
        const response = item.anomalousResponse || {};
        lines.push(`- Baseline response: HTTP ${baseline.status}, ${baseline.responseLength}${baseline.truncated ? "+" : ""} bytes, ${baseline.durationMs} ms`);
        lines.push(`- Marker response: HTTP ${response.status}, ${response.responseLength}${response.truncated ? "+" : ""} bytes, ${response.durationMs} ms; reflected=${!!response.markerReflected}${response.reflectionContext ? ` (${response.reflectionContext})` : ""}`);
        if (item.diff) lines.push(`- Difference: statusChanged=${!!item.diff.statusChanged}, responseLengthDelta=${item.diff.responseLengthDelta} bytes, durationDelta=${item.diff.durationDeltaMs} ms`);
        if (item.retest) lines.push(`- Re-test: ${item.retest.payload ? `marker \`${item.retest.payload}\`; ` : ""}${item.retest.error || `reflected=${!!item.retest.markerReflected}, HTTP ${item.retest.status}, ${item.retest.responseLength}${item.retest.truncated ? "+" : ""} bytes, ${item.retest.durationMs} ms${item.retest.reflectionContext ? ` (${item.retest.reflectionContext})` : ""}`}`);
      }
    }
  }

  lines.push("");
  lines.push(`## Reproduction notes`);
  lines.push("");
  lines.push(
    "Each finding's *Affected* URL, combined with the evidence line(s) above and, where present, the verification test performed, constitutes the reproduction steps: re-issue the same request/parameter against the affected endpoint using an authorized test account and compare against the evidence recorded here."
  );

  return lines.join("\n");
}

function countBy(arr, key) {
  const out = {};
  for (const item of arr) out[item[key]] = (out[item[key]] || 0) + 1;
  return out;
}

function severityRank(sev) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[sev] || 0;
}

function capitalize(s) {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

export function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
