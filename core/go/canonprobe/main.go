// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// canonprobe exposes the Go canonicalizers to the differential harness in
// test/conformance/differential.py, which feeds the same inputs to the Go,
// Python, JS and Lua-port references and diffs the answers.
//
// It exists because the divergences that matter are between languages, and
// nothing inside one language's test suite can see them.
//
//	go run ./canonprobe cases.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

type ipCase struct {
	Addr string `json:"addr"`
	V6   int    `json:"v6"`
	V4   int    `json:"v4"`
}

type cases struct {
	ServerNames []string `json:"server_names"`
	IPs         []ipCase `json:"ips"`
}

type results struct {
	ServerNames []string  `json:"server_names"`
	IPs         []*string `json:"ips"` // null == rejected
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: canonprobe cases.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var in cases
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out := results{
		ServerNames: make([]string, len(in.ServerNames)),
		IPs:         make([]*string, len(in.IPs)),
	}
	for i, s := range in.ServerNames {
		out.ServerNames[i] = jitcore.CanonServerName(s)
	}
	for i, c := range in.IPs {
		got, err := jitcore.CanonIP(c.Addr, c.V6, c.V4)
		if err == nil {
			v := got
			out.IPs[i] = &v
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
