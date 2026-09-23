// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"

	// Registers the redir, rewrite, try_files and file_server directives the
	// Caddyfile below uses, the same set cmd/caddy-jit compiles in.
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// The gate must run before anything that answers or reshapes a request.
//
// It was registered before `basic_auth`, which Caddy orders AFTER `redir`,
// `rewrite`, `uri` and `try_files`. So a `redir /old /new` answered 302 through
// a dark site, and the standard SPA block (`try_files {path} /index.html`)
// rewrote the challenge path to /index.html before the gate saw it: the
// challenge answered 403 and enrolled devices could never knock. The order is
// decided only when a Caddyfile is adapted, so that is what this pins.
func TestDirectiveOrderPutsGateBeforeRedirectsAndRewrites(t *testing.T) {
	const cf = `
app.example.com {
	root * /srv
	try_files {path} /index.html
	redir /old /new 302
	jit_access {
		token kid_caddy AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE test
		allow kid_caddy
	}
	file_server
}
`
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	out, warnings, err := adapter.Adapt([]byte(cf), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	for _, w := range warnings {
		t.Logf("adapter warning: %s", w.Message)
	}

	// Routes are emitted in execution order, so the byte offset of each
	// handler's JSON is its position in the chain.
	j := string(out)
	gate := strings.Index(j, `"handler":"jit_access"`)
	if gate < 0 {
		t.Fatalf("jit_access handler missing from adapted config:\n%s", j)
	}
	for _, h := range []string{
		`"handler":"rewrite"`,         // try_files
		`"handler":"static_response"`, // redir
		`"handler":"file_server"`,
	} {
		i := strings.Index(j, h)
		if i < 0 {
			t.Fatalf("%s missing from adapted config:\n%s", h, j)
		}
		if i < gate {
			t.Errorf("%s runs before the gate (offset %d < %d)", h, i, gate)
		}
	}
}
