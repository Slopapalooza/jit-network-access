// caddy-jit is a Caddy build with the jit_access handler compiled in.
//
// This exists so the module can be built with plain `go build` — no xcaddy, no
// network beyond the module cache:
//
//	go build -o caddy-jit ./cmd/caddy-jit
//
// The xcaddy path remains equivalent and is what most Caddy users will reach
// for:
//
//	xcaddy build --with github.com/Slopapalooza/jit-network-access/adapters/caddy
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// the standard Caddy module set (reverse_proxy, file_server, tls, ...)
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// the JIT Network Access gate
	_ "github.com/Slopapalooza/jit-network-access/adapters/caddy"
)

func main() {
	caddycmd.Main()
}
