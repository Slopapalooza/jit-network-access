package jitcore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	ProofDomain = "jitaccess-v1"       // domain separator for the knock proof
	NonceDomain = "jitaccess-nonce-v1" // domain separator for the nonce MAC
	NonceLen    = 56                   // 8 (ts) + 16 (rand) + 32 (mac)
)

// ---- base64url, no padding -------------------------------------------------

func B64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// B64uDecode accepts padded or unpadded input (clients differ; the wire format
// is unpadded).
func B64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// ---- primitives ------------------------------------------------------------

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// RandomBytes fails closed: an RNG error returns an error rather than degraded
// entropy, and every caller must reject on it (SPEC §7.5).
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---- proof (the knock) -----------------------------------------------------

// ProofCanonical is the exact byte string the proof MACs over.
func ProofCanonical(serverName, kid string, nonceRaw []byte) []byte {
	return PAE([]byte(ProofDomain), []byte(CanonServerName(serverName)), []byte(kid), nonceRaw)
}

// BuildProof runs identically for a real and a dummy key, so the caller can keep
// timing flat for an unknown kid instead of leaking registry membership
// (PROTOCOL §6 — the equalized-work verifier lives in the adapter).
func BuildProof(secret []byte, serverName, kid string, nonceRaw []byte) []byte {
	return hmacSHA256(secret, ProofCanonical(serverName, kid, nonceRaw))
}

// VerifyProof compares in constant time.
func VerifyProof(secret []byte, serverName, kid string, nonceRaw, tag []byte) bool {
	return hmac.Equal(BuildProof(secret, serverName, kid, nonceRaw), tag)
}

// ---- stateless nonce -------------------------------------------------------

// The nonce carries its own authentication, so /challenge stores nothing: the
// spent-set is bounded by successful knocks rather than by challenge volume and
// cannot be flooded (SECURITY-REVIEW H2/H5). Single-use is enforced separately
// by NonceStore, after the proof verifies.

func nonceMACInput(ts uint64, rand16 []byte, serverName, ip string, v6Prefix int) ([]byte, error) {
	ipc, err := CanonIP(ip, v6Prefix, 32)
	if err != nil {
		return nil, err
	}
	tsb := make([]byte, 8)
	binary.BigEndian.PutUint64(tsb, ts)
	return PAE([]byte(NonceDomain), tsb, rand16, []byte(CanonServerName(serverName)), []byte(ipc)), nil
}

// IssueNonce returns the 56-byte nonce: be64(ts) || rand16 || HMAC.
func IssueNonce(nonceKey []byte, ts uint64, rand16 []byte, serverName, ip string, v6Prefix int) ([]byte, error) {
	if len(rand16) != 16 {
		return nil, errors.New("nonce rand must be 16 bytes")
	}
	in, err := nonceMACInput(ts, rand16, serverName, ip, v6Prefix)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8, NonceLen)
	binary.BigEndian.PutUint64(out, ts)
	out = append(out, rand16...)
	return append(out, hmacSHA256(nonceKey, in)...), nil
}

// VerifyNonce checks the MAC and the freshness window. It deliberately does NOT
// enforce single-use — that is NonceStore.Claim, called only after the proof
// verifies (verify-then-burn, so a bad proof cannot consume a nonce).
//
// The nonce is bound to the service and the client IP, so one minted for
// another origin or another client will not verify here.
func VerifyNonce(nonceKey, nonce []byte, serverName, ip string, now, ttl int64, v6Prefix int) (bool, []byte) {
	if len(nonce) != NonceLen {
		return false, nil
	}
	ts := binary.BigEndian.Uint64(nonce[:8])
	rand16, mac := nonce[8:24], nonce[24:]
	in, err := nonceMACInput(ts, rand16, serverName, ip, v6Prefix)
	if err != nil {
		return false, nil
	}
	if !hmac.Equal(hmacSHA256(nonceKey, in), mac) {
		return false, nil
	}
	if now < int64(ts) || now-int64(ts) >= ttl {
		return false, nil
	}
	return true, rand16
}
