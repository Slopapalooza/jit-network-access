package jitcore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Conformance against the shared vectors (SPEC §8). These are the same bytes the
// Python generator produced and the Lua core is validated against, so passing
// here means a proof minted by the extension verifies identically whether the
// gate is BunkerWeb/Lua, the Authorizer, or the Caddy module.

const vectorsPath = "../testdata/vectors.json"

type vectors struct {
	Constants struct {
		ProofDomain   string `json:"proof_domain"`
		NonceDomain   string `json:"nonce_domain"`
		NonceLenBytes int    `json:"nonce_len_bytes"`
	} `json:"constants"`
	PAE []struct {
		Pieces []string `json:"pieces"`
		OutHex string   `json:"out_hex"`
	} `json:"pae"`
	CanonServerName []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"canon_server_name"`
	CanonIP []struct {
		In       string `json:"in"`
		V6Prefix int    `json:"v6_prefix"`
		V4Prefix int    `json:"v4_prefix"`
		Out      string `json:"out"`
	} `json:"canon_ip"`
	Proof []struct {
		SecretHex       string `json:"secret_hex"`
		ServerName      string `json:"server_name"`
		ServerNameCanon string `json:"server_name_canon"`
		Kid             string `json:"kid"`
		NonceRawHex     string `json:"nonce_raw_hex"`
		CanonicalHex    string `json:"canonical_hex"`
		ProofB64url     string `json:"proof_b64url"`
	} `json:"proof"`
	Nonce []struct {
		NonceKeyHex     string `json:"nonce_key_hex"`
		TS              int64  `json:"ts"`
		RandHex         string `json:"rand_hex"`
		ServerName      string `json:"server_name"`
		ServerNameCanon string `json:"server_name_canon"`
		IP              string `json:"ip"`
		IPCanon         string `json:"ip_canon"`
		V6Prefix        int    `json:"v6_prefix"`
		NonceHex        string `json:"nonce_hex"`
		NonceB64url     string `json:"nonce_b64url"`
		VerifyAtPlus5   bool   `json:"verify_at_ts_plus_5_ttl_60"`
	} `json:"nonce"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	v := &vectors{}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestConstants(t *testing.T) {
	v := load(t)
	if v.Constants.ProofDomain != ProofDomain {
		t.Errorf("proof domain: got %q want %q", ProofDomain, v.Constants.ProofDomain)
	}
	if v.Constants.NonceDomain != NonceDomain {
		t.Errorf("nonce domain: got %q want %q", NonceDomain, v.Constants.NonceDomain)
	}
	if v.Constants.NonceLenBytes != NonceLen {
		t.Errorf("nonce len: got %d want %d", NonceLen, v.Constants.NonceLenBytes)
	}
}

func TestPAEVectors(t *testing.T) {
	v := load(t)
	if len(v.PAE) == 0 {
		t.Fatal("no pae vectors")
	}
	for i, tc := range v.PAE {
		// the generator emits pieces as base64url-nopad
		pieces := make([][]byte, len(tc.Pieces))
		for j, p := range tc.Pieces {
			b, err := B64uDecode(p)
			if err != nil {
				t.Fatalf("pae[%d] piece %q: %v", i, p, err)
			}
			pieces[j] = b
		}
		got := hex.EncodeToString(PAE(pieces...))
		if got != tc.OutHex {
			t.Errorf("pae[%d] pieces=%v: got %s want %s", i, tc.Pieces, got, tc.OutHex)
		}
	}
}

func TestCanonServerNameVectors(t *testing.T) {
	v := load(t)
	if len(v.CanonServerName) == 0 {
		t.Fatal("no canon_server_name vectors")
	}
	for _, tc := range v.CanonServerName {
		if got := CanonServerName(tc.In); got != tc.Out {
			t.Errorf("canon_server_name(%q): got %q want %q", tc.In, got, tc.Out)
		}
	}
}

func TestCanonIPVectors(t *testing.T) {
	v := load(t)
	if len(v.CanonIP) == 0 {
		t.Fatal("no canon_ip vectors")
	}
	for _, tc := range v.CanonIP {
		got, err := CanonIP(tc.In, tc.V6Prefix, tc.V4Prefix)
		// The generator records rejected inputs as "<invalid: ...>"; those MUST
		// error here rather than canonicalize to something.
		if strings.HasPrefix(tc.Out, "<invalid") {
			if err == nil {
				t.Errorf("canon_ip(%q): expected rejection, got %q", tc.In, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("canon_ip(%q): unexpected error %v", tc.In, err)
			continue
		}
		if got != tc.Out {
			t.Errorf("canon_ip(%q, v6=%d, v4=%d): got %q want %q", tc.In, tc.V6Prefix, tc.V4Prefix, got, tc.Out)
		}
	}
}

func TestProofVectors(t *testing.T) {
	v := load(t)
	if len(v.Proof) == 0 {
		t.Fatal("no proof vectors")
	}
	for i, tc := range v.Proof {
		secret := mustHex(t, tc.SecretHex)
		nonceRaw := mustHex(t, tc.NonceRawHex)

		if got := CanonServerName(tc.ServerName); got != tc.ServerNameCanon {
			t.Errorf("proof[%d] canon: got %q want %q", i, got, tc.ServerNameCanon)
		}
		canonical := ProofCanonical(tc.ServerName, tc.Kid, nonceRaw)
		if got := hex.EncodeToString(canonical); got != tc.CanonicalHex {
			t.Errorf("proof[%d] canonical:\n got %s\nwant %s", i, got, tc.CanonicalHex)
		}
		tag := BuildProof(secret, tc.ServerName, tc.Kid, nonceRaw)
		if got := B64u(tag); got != tc.ProofB64url {
			t.Errorf("proof[%d] tag: got %s want %s", i, got, tc.ProofB64url)
		}
		if !VerifyProof(secret, tc.ServerName, tc.Kid, nonceRaw, tag) {
			t.Errorf("proof[%d]: verify of own tag failed", i)
		}
		// a flipped bit must not verify
		bad := append([]byte(nil), tag...)
		bad[0] ^= 0x01
		if VerifyProof(secret, tc.ServerName, tc.Kid, nonceRaw, bad) {
			t.Errorf("proof[%d]: tampered tag verified", i)
		}
	}
}

func TestNonceVectors(t *testing.T) {
	v := load(t)
	if len(v.Nonce) == 0 {
		t.Fatal("no nonce vectors")
	}
	for i, tc := range v.Nonce {
		key := mustHex(t, tc.NonceKeyHex)
		rand16 := mustHex(t, tc.RandHex)

		if got, err := CanonIP(tc.IP, tc.V6Prefix, 32); err != nil || got != tc.IPCanon {
			t.Errorf("nonce[%d] ip canon: got %q err %v want %q", i, got, err, tc.IPCanon)
		}
		n, err := IssueNonce(key, uint64(tc.TS), rand16, tc.ServerName, tc.IP, tc.V6Prefix)
		if err != nil {
			t.Fatalf("nonce[%d] issue: %v", i, err)
		}
		if got := hex.EncodeToString(n); got != tc.NonceHex {
			t.Errorf("nonce[%d]:\n got %s\nwant %s", i, got, tc.NonceHex)
		}
		if got := B64u(n); got != tc.NonceB64url {
			t.Errorf("nonce[%d] b64: got %s want %s", i, got, tc.NonceB64url)
		}

		ok, gotRand := VerifyNonce(key, n, tc.ServerName, tc.IP, tc.TS+5, 60, tc.V6Prefix)
		if ok != tc.VerifyAtPlus5 {
			t.Errorf("nonce[%d] verify at +5: got %v want %v", i, ok, tc.VerifyAtPlus5)
		}
		if ok && !bytes.Equal(gotRand, rand16) {
			t.Errorf("nonce[%d]: returned rand mismatch", i)
		}
		// outside the TTL window, and before it was minted
		if ok, _ := VerifyNonce(key, n, tc.ServerName, tc.IP, tc.TS+60, 60, tc.V6Prefix); ok {
			t.Errorf("nonce[%d]: verified at ts+ttl (should be stale)", i)
		}
		if ok, _ := VerifyNonce(key, n, tc.ServerName, tc.IP, tc.TS-1, 60, tc.V6Prefix); ok {
			t.Errorf("nonce[%d]: verified before its timestamp", i)
		}
		// bound to service and client IP
		if ok, _ := VerifyNonce(key, n, "other."+tc.ServerName, tc.IP, tc.TS+5, 60, tc.V6Prefix); ok {
			t.Errorf("nonce[%d]: verified for a different service", i)
		}
	}
}
