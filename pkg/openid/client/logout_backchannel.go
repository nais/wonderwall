package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/nais/wonderwall/pkg/openid"
)

const (
	BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

	logoutTokenMaxAge             = 5 * time.Minute
	logoutBackChannelMaxBodyBytes = 64 * 1024

	eventsClaim = "events"
	nonceClaim  = "nonce"
)

var (
	ErrLogoutBackChannelMalformedRequest = errors.New("back-channel logout: malformed request")
	ErrLogoutBackChannelMissingToken     = errors.New("back-channel logout: missing logout_token")
	ErrLogoutBackChannelInvalidToken     = errors.New("back-channel logout: invalid logout_token")
)

// LogoutBackChannel reads and validates the logout token from a back-channel logout request, as defined in
// OpenID Connect Back-Channel Logout 1.0, sections 2.5 and 2.6. It returns the token's `sid` claim.
func (c *Client) LogoutBackChannel(w http.ResponseWriter, r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, logoutBackChannelMaxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrLogoutBackChannelMalformedRequest, err)
	}

	raw := r.PostForm.Get("logout_token")
	if raw == "" {
		return "", ErrLogoutBackChannelMissingToken
	}

	jwks, err := c.jwksProvider.GetPublicJwkSet(r.Context())
	if err != nil {
		return "", fmt.Errorf("getting jwks: %w", err)
	}

	if err := verifyLogoutTokenSignature(raw, jwks); err != nil {
		// The provider may have rotated its signing keys since they were cached. Refreshes are throttled.
		jwks, err = c.jwksProvider.RefreshPublicJwkSet(r.Context())
		if err != nil {
			return "", fmt.Errorf("refreshing jwks: %w", err)
		}
		if err := verifyLogoutTokenSignature(raw, jwks); err != nil {
			return "", fmt.Errorf("%w: %w", ErrLogoutBackChannelInvalidToken, err)
		}
	}

	sid, err := c.validateLogoutTokenClaims(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLogoutBackChannelInvalidToken, err)
	}

	return sid, nil
}

func verifyLogoutTokenSignature(raw string, jwks *jwk.Set) error {
	if _, err := jws.Verify([]byte(raw),
		jws.WithKeySet(*jwks),
		jws.WithAlgorithmMatch(true),
	); err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}
	return nil
}

// validateLogoutTokenClaims validates the claims of a logout token whose signature has already been verified.
func (c *Client) validateLogoutTokenClaims(raw string) (string, error) {
	token, err := jwt.ParseString(raw,
		jwt.WithVerify(false), // signature is verified by the caller because WithAlgorithmMatch isn't accepted here
		jwt.WithAcceptableSkew(openid.AcceptableSkew),
		jwt.WithIssuer(c.cfg.Provider().Issuer()),
		jwt.WithAudience(c.cfg.Client().ClientID()),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		// now - iat <= max age; an empty claim name refers to the current time.
		jwt.WithMaxDelta(logoutTokenMaxAge, "", jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
	)
	if err != nil {
		return "", err
	}

	if err := openid.ValidateAudiences(token, c.cfg.Client()); err != nil {
		return "", err
	}

	// Step 5: require the back-channel logout event.
	var events map[string]any
	if err := token.Get(eventsClaim, &events); err != nil {
		return "", fmt.Errorf("missing or malformed %q claim: %w", eventsClaim, err)
	}
	event, ok := events[BackChannelLogoutEvent]
	if !ok {
		return "", fmt.Errorf("%q claim does not contain %q", eventsClaim, BackChannelLogoutEvent)
	}
	if _, ok := event.(map[string]any); !ok {
		return "", fmt.Errorf("%q event value must be a JSON object", BackChannelLogoutEvent)
	}

	// Step 6 allows tokens with only `sub`, but sessions can only be found by `sid`.
	var sid string
	if err := token.Get(openid.SidClaim, &sid); err != nil || sid == "" {
		return "", fmt.Errorf("missing or invalid %q claim; logout by %q alone is not supported", openid.SidClaim, "sub")
	}

	// Step 7: a nonce claim must not be present, to prevent confusion with ID tokens.
	if token.Has(nonceClaim) {
		return "", fmt.Errorf("must not contain a %q claim", nonceClaim)
	}

	return sid, nil
}
