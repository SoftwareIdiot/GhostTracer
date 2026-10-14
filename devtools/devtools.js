// Registers the GhostTrace DevTools panel.
chrome.devtools.panels.create(
  "GhostTrace",
  "icons/icon48.png",
  "panel/dist/index.html",
  (panel) => {
    // no-op: panel UI handles its own lifecycle
  }
);
