package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	proofType = "dpop+jwt"

	claimHTTPMethod = "htm"
	claimHTTPURI    = "htu"
	claimAccessHash = "ath"
)

// Proofer creates DPoP proofs with one private signing key.
type Proofer struct {
	key        jwk.Key
	publicKey  jwk.Key
	alg        jwa.SignatureAlgorithm
	thumbprint string
}

// NewProofer creates a proofer from a private asymmetric signing key.
func NewProofer(key jwk.Key) (*Proofer, error) {
	if key == nil {
		return nil, fmt.Errorf("dpop: key is nil")
	}

	algorithm, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf("dpop: key is missing an algorithm")
	}
	alg, ok := algorithm.(jwa.SignatureAlgorithm)
	if !ok || alg == jwa.NoSignature() || alg.IsSymmetric() {
		return nil, fmt.Errorf("dpop: key algorithm %q is not an asymmetric signature algorithm", algorithm.String())
	}
	private, err := jwk.IsPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("dpop: checking private key: %w", err)
	}
	if !private {
		return nil, fmt.Errorf("dpop: key is not private")
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("dpop: getting public key: %w", err)
	}
	thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dpop: creating thumbprint: %w", err)
	}

	return &Proofer{
		key:        key,
		publicKey:  publicKey,
		alg:        alg,
		thumbprint: base64.RawURLEncoding.EncodeToString(thumbprint),
	}, nil
}

// Proof creates a signed DPoP proof.
func (p *Proofer) Proof(ctx context.Context, method string, targetURL *url.URL, nonce, accessToken string) ([]byte, error) {
	_, span := otel.StartSpan(ctx, "DPoP.Proof")
	defer span.End()

	if targetURL == nil {
		return nil, fmt.Errorf("dpop: target URL is nil")
	}

	htm := method
	htu := stripTarget(targetURL).String()

	builder := jwt.NewBuilder().
		Claim(claimHTTPMethod, htm).
		Claim(claimHTTPURI, htu).
		JwtID(uuid.NewString()).
		IssuedAt(time.Now())
	if nonce != "" {
		builder.Claim("nonce", nonce)
	}
	if accessToken != "" {
		digest := sha256.Sum256([]byte(accessToken))
		builder.Claim(claimAccessHash, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
	claims, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("dpop: building proof: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, proofType); err != nil {
		return nil, fmt.Errorf("dpop: setting typ header: %w", err)
	}
	if err := headers.Set(jws.JWKKey, p.publicKey); err != nil {
		return nil, fmt.Errorf("dpop: setting jwk header: %w", err)
	}

	encoded, err := jwt.Sign(claims, jwt.WithKey(p.alg, p.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("dpop: signing proof: %w", err)
	}

	span.SetAttributes(attribute.String("dpop.htm", htm))
	span.SetAttributes(attribute.String("dpop.htu", htu))
	span.SetAttributes(attribute.String("dpop.jkt", p.thumbprint))
	return encoded, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the public JWK.
func (p *Proofer) Thumbprint() string {
	return p.thumbprint
}

// TargetURI returns the htu target for a request received at the given public base URL.
func TargetURI(base *url.URL, r *http.Request) *url.URL {
	target := *base
	target.Path = r.URL.Path
	target.RawPath = r.URL.RawPath
	return stripTarget(&target)
}

// stripTarget removes the query and fragment parts, which RFC 9449, section 4.2 excludes from htu.
func stripTarget(target *url.URL) *url.URL {
	result := *target
	result.RawQuery = ""
	result.ForceQuery = false
	result.Fragment = ""
	result.RawFragment = ""
	return &result
}
