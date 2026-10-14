import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { buildGraphElements } from "../lib/graphModel.js";

cytoscape.use(dagre);

const STYLE = [
  { selector: "node", style: { "label": "data(label)", "font-size": 9, "color": "#cfd3da", "text-wrap": "wrap", "text-max-width": "110px", "text-valign": "bottom", "text-margin-y": 4 } },
  { selector: "node[kind='page']", style: { shape: "round-rectangle", "background-color": "#1b2a3a", "border-color": "#5fb4ff", "border-width": 1.5, width: 26, height: 26 } },
  { selector: "node[kind='request']", style: { shape: "ellipse", "background-color": "#1b2430", "border-color": "#6b7280", "border-width": 1, width: 18, height: 18 } },
  { selector: "node[kind='finding']", style: { shape: "diamond", "background-color": "#2a1b1b", "border-color": "#c0392b", "border-width": 1.5, width: 24, height: 24 } },
  { selector: "node[kind='finding'][severity='medium']", style: { "border-color": "#c9a227" } },
  { selector: "node[kind='finding'][severity='low']", style: { "border-color": "#6b7280" } },
  { selector: "node[kind='verify'][outcome='positive']", style: { "background-color": "#2a1b1b", "border-color": "#ff8c8c", "border-width": 2, shape: "star", width: 22, height: 22 } },
  { selector: "node[kind='verify'][outcome='negative']", style: { "background-color": "#16241c", "border-color": "#2f8f52", shape: "star", width: 20, height: 20 } },
  { selector: "node[kind='verify'][outcome='error']", style: { "background-color": "#1f1f1f", "border-color": "#6b7280", shape: "star", width: 18, height: 18 } },
  { selector: "edge", style: { width: 1, "line-color": "#333a47", "target-arrow-color": "#333a47", "target-arrow-shape": "triangle", "curve-style": "bezier", "font-size": 8, "color": "#6b7280", label: "data(label)", "text-rotation": "autorotate", "text-margin-y": -4 } }
];

export default function MapGraph({ evidence, findings }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      style: STYLE,
      elements: [],
      wheelSensitivity: 0.3
    });
    cy.on("tap", "node", (evt) => setSelected(evt.target.data()));
    cy.on("tap", (evt) => { if (evt.target === cy) setSelected(null); });
    cyRef.current = cy;
    return () => cy.destroy();
  }, []);

  useEffect(() => {
    if (!cyRef.current || !evidence) return;
    const { nodes, edges } = buildGraphElements(evidence, findings);
    cyRef.current.elements().remove();
    cyRef.current.add([...nodes, ...edges]);
    cyRef.current.layout({ name: "dagre", rankDir: "TB", nodeSep: 24, rankSep: 60, animate: false }).run();
  }, [evidence, findings]);

  const hasData = evidence && (Object.keys(evidence.pages || {}).length > 0 || (evidence.requests || []).length > 0);

  return (
    <div>
      <div style={{ display: "flex", gap: 14, fontSize: 11, color: "#8a8f98", marginBottom: 8 }}>
        <Legend swatch="#5fb4ff" label="Page" />
        <Legend swatch="#6b7280" label="Request" />
        <Legend swatch="#c0392b" label="Finding" />
        <Legend swatch="#ff8c8c" label="Verify result" />
      </div>
      <div className="graph-wrap" ref={containerRef} />
      {!hasData && <div className="empty">Graph will populate as pages and requests are observed.</div>}
      {selected && (
        <div className="card" style={{ marginTop: 10 }}>
          <h3>{selected.label}</h3>
          <div className="meta">kind: {selected.kind}{selected.severity ? ` · severity: ${selected.severity}` : ""}{selected.confidence ? ` · confidence: ${selected.confidence}` : ""}</div>
        </div>
      )}
    </div>
  );
}

function Legend({ swatch, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span style={{ width: 8, height: 8, borderRadius: 2, background: swatch, display: "inline-block" }} />
      {label}
    </div>
  );
}
