package jitcore

import "errors"

// TokenRegistry (SPEC §3). Pure over its input: the adapter parses backend
// config (BunkerWeb settings, Authorizer config file) into these maps and hands
// them in, so there is no I/O on the request path.

const AlgHMACSHA256 = "HMAC-SHA256"

type Token struct {
	Secret  []byte // raw bytes, not base64
	Alg     string // pinned per kid; a mismatch is failure, never a downgrade
	Label   string
	Expires int64 // unix seconds; 0 = never
}

// Registry is read-only at request time. Swap it wholesale on config reload
// (atomically, from the adapter) rather than mutating it under readers.
type Registry struct {
	Tokens map[string]*Token
	// Services maps canonical server_name -> allowed kids. The key "*" means
	// "any registered token may open this service".
	Services map[string]map[string]bool
}

func NewRegistry(tokens map[string]*Token, services map[string]map[string]bool) *Registry {
	if tokens == nil {
		tokens = map[string]*Token{}
	}
	if services == nil {
		services = map[string]map[string]bool{}
	}
	return &Registry{Tokens: tokens, Services: services}
}

func (r *Registry) Lookup(kid string) *Token {
	if r == nil {
		return nil
	}
	return r.Tokens[kid]
}

func (r *Registry) IsExpired(t *Token, now int64) bool {
	return t != nil && t.Expires != 0 && now >= t.Expires
}

// AllowedForService answers the per-service allow-list for an already-canonical
// server name.
func (r *Registry) AllowedForService(kid, serviceCanon string) bool {
	if r == nil {
		return false
	}
	svc, ok := r.Services[serviceCanon]
	if !ok {
		return false
	}
	return svc["*"] || svc[kid]
}

var (
	ErrUnknownKid   = errors.New("unknown kid")
	ErrTokenExpired = errors.New("token expired")
	ErrNotAllowed   = errors.New("kid not allowed for service")
)

// Authorize is the full policy check for a knock: known kid, not expired, and
// permitted for this service. The caller still verifies the proof separately —
// and must run the equalized-work dummy verify when this returns an error, so
// the response does not reveal whether the kid exists.
func (r *Registry) Authorize(kid, serviceCanon string, now int64) (*Token, error) {
	t := r.Lookup(kid)
	if t == nil {
		return nil, ErrUnknownKid
	}
	if r.IsExpired(t, now) {
		return nil, ErrTokenExpired
	}
	if !r.AllowedForService(kid, serviceCanon) {
		return nil, ErrNotAllowed
	}
	return t, nil
}
