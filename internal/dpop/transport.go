package dpop

import (
	"fmt"
	"net/http"
	"sync"
)

const (
	proofHeader = "DPoP"
	nonceHeader = "DPoP-Nonce"
)

// Transport adds DPoP proofs to requests sent to one token endpoint.
// It captures nonce challenges for the caller, which retries above the transport
// so each retry can create fresh client authentication parameters and a proof.
type Transport struct {
	base     http.RoundTripper
	proofer  *Proofer
	tokenURL string

	nonceMu sync.RWMutex
	nonce   string
}

// NewTransport wraps base and limits DPoP injection to tokenURL.
func NewTransport(base http.RoundTripper, tokenURL string, proofer *Proofer) (*Transport, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	if proofer == nil {
		return nil, fmt.Errorf("dpop: proofer is nil")
	}

	r, err := http.NewRequest(http.MethodPost, tokenURL, nil)
	if err != nil || r.URL.Scheme == "" || r.URL.Host == "" {
		return nil, fmt.Errorf("dpop: invalid token URL %q", tokenURL)
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return nil, fmt.Errorf("dpop: token URL must use HTTP or HTTPS")
	}
	if r.URL.User != nil {
		return nil, fmt.Errorf("dpop: token URL must not contain user info")
	}
	if r.URL.Fragment != "" {
		return nil, fmt.Errorf("dpop: token URL must not contain a fragment")
	}

	return &Transport{base: base, proofer: proofer, tokenURL: r.URL.String()}, nil
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, fmt.Errorf("dpop: request is nil")
	}
	if r.URL.String() != t.tokenURL {
		return t.base.RoundTrip(r)
	}

	ctx := r.Context()
	requestCopy := r.Clone(ctx)
	proof, err := t.proofer.Proof(ctx, r.Method, r.URL, t.nonceValue(), "")
	if err != nil {
		return nil, err
	}

	requestCopy.Header.Set(proofHeader, string(proof))
	response, err := t.base.RoundTrip(requestCopy)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("dpop: wrapped transport returned a nil response")
	}

	t.captureNonce(response)
	return response, nil
}

func (t *Transport) nonceValue() string {
	t.nonceMu.RLock()
	defer t.nonceMu.RUnlock()
	return t.nonce
}

func (t *Transport) captureNonce(response *http.Response) {
	if nonce := response.Header.Get(nonceHeader); nonce != "" {
		t.nonceMu.Lock()
		t.nonce = nonce
		t.nonceMu.Unlock()
	}
}
