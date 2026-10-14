# GhostTrace

I started GhostTrace because I wanted a better way to connect what a browser sees with the questions a web security assessment needs to answer. A list of warnings on its own is easy to ignore; it is more useful to see which page led to a request, what evidence was actually collected, and what still needs a tester to verify it.

GhostTrace is my evolving, browser-based web application assessment workbench. It combines a Chrome/Edge extension with a separate local dashboard. I am building it as I learn, so some checks are deliberately modest and the project is still a work in progress.

## A careful workflow

GhostTrace is organized around observing first and testing deliberately:

1. **Activate one origin.** Collection is off until you activate the current site in the extension popup.
2. **Browse normally.** GhostTrace records browser-visible assessment evidence for that origin, such as page and route details, request metadata, forms, scripts, and storage or cookie metadata.
3. **Review the map and signals.** The DevTools panel links observed pages, requests, and findings. Passive checks mark observations that may deserve attention; a signal is not proof of a vulnerability.
4. **Verify a hypothesis yourself.** The Verify panel offers a small set of manual, one-at-a-time checks. Active requests are not sent automatically when a site is activated.
5. **Keep the assessment together.** Use the separate dashboard to review activated sites, track finding status and notes, and export a Markdown or JSON report.

The goal is to make the evidence and the remaining questions easier to follow, not to fire payloads at every input. Use GhostTrace only on applications you own or have clear permission to assess.

## What it can collect and check

- Requests and response metadata visible through the browser extension APIs.
- Page URLs, route changes, forms, fields, links, scripts, and basic technology hints.
- Cookie flags and browser storage metadata such as key names and approximate value lengths; values are not collected by the storage-metadata observer.
- Passive signals for security headers, cookie configuration, sensitive-looking field names, exposed-secret patterns, dependency hints, redirect patterns, and client-side injection candidates.
- Tester notes, review status, severity adjustments, manual findings, and verification results.
- A graph that connects observed pages, requests, findings, and verification results where the available evidence supports the link.

Some checks are heuristic by design. For example, a dependency hint is not a complete vulnerability database, and a possible DOM injection path is not a confirmed XSS finding. Non-document response bodies are not captured, so GhostTrace cannot inspect arbitrary API response content. Treat the output as assessment evidence to review, not a substitute for manual analysis or a dedicated scanner.

## Local setup

You will need Node.js 18 or newer, npm, and a recent Chrome or Edge browser.

### Build the extension UI

From the project folder:

```powershell
cd panel
npm install
npm run build
```

The build creates `panel/dist/`, including the DevTools panel and the bundled assessment dashboard. Generated build files are intentionally not committed; build them locally before loading the unpacked extension.

### Load the extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this project folder, the one containing `manifest.json`.
4. Open a normal HTTP or HTTPS site you are authorized to assess, then use the GhostTrace toolbar popup to activate observation for that origin.

The extension also registers a GhostTrace panel in browser DevTools. Open DevTools and select that panel to review the current tab's Observe, Map, Findings, Verify, and Report views.

### Run the dashboard during development

The panel's Vite server can serve the separate dashboard at `http://127.0.0.1:5173/dashboard.html`:

```powershell
cd panel
npm run dev
```

Keep the server running and choose **Open assessment dashboard** in the extension popup. The popup uses this local page during development and falls back to the bundled dashboard after you build the panel.

## Where assessment data lives

The dashboard is a local companion to the extension, not a hosted service. It connects to the extension in the same browser profile, and site evidence and assessment notes are stored in `chrome.storage.local`. This project does not currently provide an account system, cloud sync, or a remote backend. Keep that in mind when choosing a browser profile and when clearing extension data.

The manifest requests access to HTTP and HTTPS sites so the extension can be activated on a site when you choose. Collection is gated by per-origin activation; the extension is not intended to assess every site simply because it is installed. The dashboard connection is restricted to local development origins.

## Project layout

```text
ghosttrace/
  manifest.json                 # Chrome/Edge Manifest V3 configuration
  background/
    background.js               # Activation, evidence storage, messages, and manual verification
    detectionEngine.js          # Passive checks shared with the assessment UI
    ActiveEngine.js             # Isolated active-test engine; not auto-run on activation
  content/
    content-script.js           # Activation-gated page and DOM observation
  popup/                        # Per-origin activation and dashboard launch
  devtools/                     # GhostTrace DevTools panel registration
  panel/
    src/                        # React panel, map, findings, verification, reports, and dashboard entry
    vite.config.js
  dashboard/
    src/                        # Separate local assessment dashboard and extension bridge
  icons/
```

## How I want to grow it

I want GhostTrace to become more useful by making its evidence clearer and its checks more reliable. The next steps I have in mind are better page-to-request correlation, stronger confidence explanations, more precise manual verification flows, and tests that help catch regressions without sending traffic to real sites. The current graph and passive detectors are a starting point, not a claim that every relationship or vulnerability has been proven.

If you try it, feedback on confusing findings, missing context, or a safer way to verify a hypothesis is especially helpful.
