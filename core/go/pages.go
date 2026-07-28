// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

// Shared HTML served by every Go engine.
//
// Lives in the core rather than being copied into each adapter because the
// interstitial already IS copied three times, and keeping user-facing text in
// step by hand across engines is exactly the drift the shared vectors exist to
// prevent for the crypto.

// ExtensionReleasesURL is where a browser without the extension is sent to get
// it. Forks and air-gapped sites that mirror the artifact internally should
// change this in one place.
const ExtensionReleasesURL = "https://github.com/Slopapalooza/jit-network-access/releases"

// RegisterHTML is the registration landing page.
//
// A registration link points at <prefix>/register?code=... on the protected
// origin. When the extension IS installed its service worker intercepts that
// navigation before the request ever leaves the browser and swaps in its own
// consent page — so this HTML is only ever seen by someone who does NOT have the
// extension, which makes it exactly the right place to tell them how to get it.
//
// Deliberately static. It says nothing about whether the code in the URL is
// valid, unused or expired, so it is not an oracle for enrollment codes. The
// code is not echoed into the page either: it is a single-use credential, and
// reflecting it would put it in the DOM, in any screenshot, and in the referrer
// of every link on the page.
var RegisterHTML = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Install the JIT Network Access extension</title>
<style>
  body { font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
         color: #24313f; background: #f4f6f8; margin: 0;
         display: flex; min-height: 100vh; align-items: center; justify-content: center; }
  .card { background: #fff; border: 1px solid #e2e7ec; border-radius: 10px;
          padding: 2rem; max-width: 34rem; margin: 1rem; }
  h1 { font-size: 1.2rem; margin: 0 0 .6rem; }
  p { margin: .6rem 0 0; color: #67727e; }
  ol { margin: .8rem 0 0; padding-left: 1.2rem; color: #67727e; }
  li { margin: .3rem 0; }
  a.btn { display: inline-block; margin-top: 1rem; padding: .5rem .9rem;
          background: #2f6feb; color: #fff; border-radius: 6px; text-decoration: none; }
  code { background: #f4f6f8; padding: .1rem .3rem; border-radius: 3px; }
</style>
</head>
<body>
  <div class="card">
    <h1>Install the JIT Network Access extension</h1>
    <p>This is an enrollment link, but the extension is not installed in this
       browser — so there is nothing here to receive it yet.</p>
    <ol>
      <li>Download the latest <code>jit-access-&lt;version&gt;.zip</code> from the releases page and unzip it.</li>
      <li>Open <code>chrome://extensions</code> and turn on <b>Developer mode</b>.</li>
      <li>Choose <b>Load unpacked</b> and select the unzipped folder.</li>
      <li>Come back and open this enrollment link again.</li>
    </ol>
    <a class="btn" href="` + ExtensionReleasesURL + `" rel="noopener noreferrer">Get the extension</a>
    <p>Already installed? Make sure it is enabled, then reload this page. The
       extension takes over enrollment links automatically.</p>
  </div>
</body>
</html>
`)
