// Package jitcore is the Go reference implementation of the JIT Network Access
// portable core (L3). It is the library the standalone Authorizer and the native
// Caddy module embed, and it is the second implementation (after core/lua) that
// must agree byte-for-byte with core/testdata/vectors.json.
//
// See ../SPEC.md for the interface contract and ../../docs/PROTOCOL.md for the
// wire format. The pure parts of this package (PAE, canonicalization, proof and
// nonce crypto) are fully pinned by the shared vectors; vectors_test.go asserts
// every one of them. The only stateful parts are GrantStore and NonceStore.
package jitcore

import "encoding/binary"

// LE64 is the PASETO length encoding: 8-byte little-endian with the top bit of
// the final byte cleared.
func LE64(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	b[7] &= 0x7f
	return b
}

// PAE is Pre-Authentication Encoding (PROTOCOL §5.1).
//
// Concatenating variable-length fields before a MAC is not injective: distinct
// field lists can produce identical bytes, which allowed a cross-service proof
// collision in the original draft (SECURITY-REVIEW H1). Length-prefixing every
// piece — and the piece count — makes the encoding injective, so a proof minted
// for one (service, kid, nonce) can never be reinterpreted as another.
func PAE(pieces ...[]byte) []byte {
	n := 8
	for _, p := range pieces {
		n += 8 + len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, LE64(uint64(len(pieces)))...)
	for _, p := range pieces {
		out = append(out, LE64(uint64(len(p)))...)
		out = append(out, p...)
	}
	return out
}
