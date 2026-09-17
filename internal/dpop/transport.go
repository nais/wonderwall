package dpop

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	normalized, err := normalizeTokenURL(tokenURL)
	if err != nil {
		return nil, err
	}
	return &Transport{base: base, proofer: proofer, tokenURL: normalized}, nil
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, fmt.Errorf("dpop: request is nil")
	}
	requestURL, err := normalizeTokenURL(r.URL.String())
	if err != nil || requestURL != t.tokenURL {
		return t.base.RoundTrip(r)
	}
	proofTarget, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("dpop: parsing normalized token URL: %w", err)
	}

	ctx := r.Context()
	requestCopy := r.Clone(ctx)
	proof, err := t.proofer.Proof(ctx, r.Method, proofTarget, t.nonceValue(), "")
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

func normalizeTokenURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("dpop: invalid token URL %q", value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("dpop: token URL must not contain user info")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme == "https" && parsed.Port() == "443" || parsed.Scheme == "http" && parsed.Port() == "80" {
		parsed.Host = parsed.Hostname()
	}
	return parsed.String(), nil
}
