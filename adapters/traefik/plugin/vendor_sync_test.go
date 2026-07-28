// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// internal/jitcore is a COMMITTED copy of core/go, produced by build-vendor.sh —
// Yaegi interprets this plugin at load time and cannot fetch modules, so the core
// has to travel with it.
//
// That makes it the one place in the repo where a fix to the shared core does not
// reach an engine. It happened: core/go and core/lua both gained IPv6 strictness
// fixes and a rewritten canon_server_name while this copy kept the old code, so
// the Traefik plugin would have shipped canonicalization that disagreed with
// every other engine about grant keys and MAC inputs.
//
// Nothing else catches it. The plugin's own tests pass against whatever is
// vendored — a stale copy is self-consistent, just wrong.
func TestVendoredCoreIsInSyncWithCoreGo(t *testing.T) {
	const src, dst = "../../../core/go", "internal/jitcore"

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}

	want := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		// build-vendor.sh copies the top-level non-test .go files only:
		// subdirectories are separate packages and tests read ../testdata,
		// which does not exist under the plugin.
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		want[n] = true

		a, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		b, err := os.ReadFile(filepath.Join(dst, n))
		if err != nil {
			t.Errorf("%s is missing from %s — run build-vendor.sh", n, dst)
			continue
		}
		if string(a) != string(b) {
			t.Errorf("%s has drifted from core/go — run build-vendor.sh\n"+
				"  vendored copy is %d bytes, core/go is %d", n, len(b), len(a))
		}
	}

	if len(want) == 0 {
		t.Fatal("found no core/go sources to compare — the paths are wrong")
	}

	// A file deleted from core/go must not linger here still being compiled in.
	vendored, err := os.ReadDir(dst)
	if err != nil {
		t.Fatalf("read %s: %v", dst, err)
	}
	for _, e := range vendored {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !want[n] {
			t.Errorf("%s/%s is not in core/go — run build-vendor.sh", dst, n)
		}
	}
}
