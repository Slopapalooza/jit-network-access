package main

const (
	// JITMarker is the detection hook the extension looks for on a denied
	// response (PROTOCOL §7). Byte-identical to the BunkerWeb plugin's marker so
	// one client works against either engine.
	JITMarker = "challenge; v=1"

	// GrantCookieName carries the opaque grant id for ip+cookie binding. It is
	// host-only (no Domain attribute) and SameSite=Strict.
	GrantCookieName = "__Host-jit-grant"
)

// The interstitial body: no branding, no detail about why access was refused,
// and no hint about what would satisfy the gate beyond the marker header.
var interstitialHTML = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device authorization required</title>
<style>
  body { font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
         color: #24313f; background: #f4f6f8; margin: 0;
         display: flex; min-height: 100vh; align-items: center; justify-content: center; }
  .card { background: #fff; border: 1px solid #e2e7ec; border-radius: 10px;
          padding: 2rem; max-width: 30rem; margin: 1rem; }
  h1 { font-size: 1.2rem; margin: 0 0 .6rem; }
  p { margin: .5rem 0 0; color: #67727e; }
</style>
</head>
<body>
  <div class="card">
    <h1>Device authorization required</h1>
    <p>This service is restricted to enrolled devices. If your device is
       enrolled, authorization happens automatically — reload the page.</p>
    <p>Otherwise contact your administrator to enroll this device.</p>
  </div>
</body>
</html>
`)
