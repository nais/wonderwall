package openid

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid/acr"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

const (
	AcrClaim      = "acr"
	AmrClaim      = "amr"
	AuthTimeClaim = "auth_time"
	LocaleClaim   = "locale"
	SidClaim      = "sid"
	OidClaim      = "oid"

	AcceptableSkew = 5 * time.Second
)

type Tokens struct {
	AccessToken  string
	Expiry       time.Time
	IDToken      *IDToken
	RefreshToken string
	TokenType    string
}

func NewTokens(src *oauth2.Token, jwks *jwk.Set, cfg openidconfig.Config, cookie *LoginCookie) (*Tokens, error) {
	rawIdToken, ok := src.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	idToken, err := ParseIDToken(rawIdToken)
	if err != nil {
		return nil, fmt.Errorf("parsing id_token: %w", err)
	}

	expectedAcr := cookie.Acr
	expectedNonce := cookie.Nonce
	if err := idToken.Validate(cfg, expectedAcr, expectedNonce, jwks); err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	return &Tokens{
		AccessToken:  src.AccessToken,
		Expiry:       src.Expiry,
		IDToken:      idToken,
		RefreshToken: src.RefreshToken,
		TokenType:    src.TokenType,
	}, nil
}

func NewIDToken(raw string, jwtToken jwt.Token) *IDToken {
	return &IDToken{
		serialized: raw,
		Token:      jwtToken,
	}
}

// ParseIDToken parses a raw ID token string into an IDToken struct.
// It does not validate the token nor verify the signature.
func ParseIDToken(raw string) (*IDToken, error) {
	opts := []jwt.ParseOption{
		jwt.WithValidate(false), // JWT validation is done in IDToken.Validate
		jwt.WithVerify(false),   // Signature verification is done in IDToken.Validate
	}
	idToken, err := jwt.ParseString(raw, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	return NewIDToken(raw, idToken), nil
}

type IDToken struct {
	serialized string
	jwt.Token
}

func (in *IDToken) Validate(cfg openidconfig.Config, expectedAcr, expectedNonce string, jwks *jwk.Set) error {
	openIDconfig := cfg.Provider()
	clientConfig := cfg.Client()

	_, err := jws.Verify([]byte(in.Serialized()), jws.WithKeySet(*jwks))
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	opts := []jwt.ValidateOption{
		// OpenID Connect Core, section 2 - required claims.
		jwt.WithRequiredClaim("iss"),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("aud"),
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("iat"),
		// OpenID Connect Core section 3.1.3.7, step 2.
		//  The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the `iss` (issuer) Claim.
		jwt.WithIssuer(openIDconfig.Issuer()),
		// OpenID Connect Core section 3.1.3.7, step 3.
		//  The Client MUST validate that the `aud` (audience) Claim contains its `client_id` value registered at the Issuer identified by the `iss` (issuer) Claim as an audience.
		//  The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience
		jwt.WithAudience(clientConfig.ClientID()),

		// Skew tolerance for time-based claims (exp, iat, nbf)
		jwt.WithAcceptableSkew(AcceptableSkew),
	}
	if expectedNonce != "" {
		// OpenID Connect Core section 3.1.3.7, step 11.
		//  If a nonce value was sent in the Authentication Request, a `nonce` Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request.
		opts = append(opts, jwt.WithClaimValue("nonce", expectedNonce))
	}

	if openIDconfig.SidClaimRequired() {
		opts = append(opts, jwt.WithRequiredClaim(SidClaim))
	}

	// OpenID Connect Core 3.1.3.7, step 12.
	//  If the `acr` Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
	if len(clientConfig.ACRValues()) > 0 {
		opts = append(opts, jwt.WithRequiredClaim(AcrClaim))
		if expectedAcr != "" {
			err := acr.Validate(expectedAcr, in.Acr())
			if err != nil {
				return err
			}
		}
	}

	if err := jwt.Validate(in.Token, opts...); err != nil {
		return err
	}

	// OpenID Connect Core 3.1.3.7, step 3.
	//  The `aud` (audience) Claim MAY contain an array with more than one element.
	//  The ID Token MUST be rejected if the ID Token [...] contains additional audiences not trusted by the Client.
	audiences, ok := in.Audience()
	if !ok {
		return fmt.Errorf("missing required 'aud' claim in id_token")
	}
	if len(audiences) > 1 {
		trusted := clientConfig.Audiences()
		untrusted := make([]string, 0)

		for _, audience := range audiences {
			if !trusted[audience] {
				untrusted = append(untrusted, audience)
			}
		}

		if len(untrusted) > 0 {
			return fmt.Errorf("'aud' not satisfied, untrusted audience(s) found: %q", untrusted)
		}
	}

	return nil
}

func (in *IDToken) Acr() string {
	return in.StringClaimOrEmpty(AcrClaim)
}

func (in *IDToken) Amr() string {
	s := in.StringClaimOrEmpty(AmrClaim)
	if len(s) == 0 {
		s = strings.Join(in.StringSliceClaimOrEmpty(AmrClaim), ",")
	}

	return s
}

func (in *IDToken) AuthTime() time.Time {
	return in.TimeClaim(AuthTimeClaim)
}

func (in *IDToken) Locale() string {
	return in.StringClaimOrEmpty(LocaleClaim)
}

func (in *IDToken) Oid() string {
	return in.StringClaimOrEmpty(OidClaim)
}

func (in *IDToken) Sid() (string, error) {
	return in.StringClaim(SidClaim)
}

func (in *IDToken) Serialized() string {
	return in.serialized
}

func (in *IDToken) Claim(claim string) (any, error) {
	if in.Token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	var gotClaim any
	if err := in.Token.Get(claim, &gotClaim); err != nil {
		return nil, fmt.Errorf("missing required '%s' claim in id_token: %w", claim, err)
	}

	return gotClaim, nil
}

func (in *IDToken) StringClaim(claim string) (string, error) {
	gotClaim, err := in.Claim(claim)
	if err != nil {
		return "", err
	}

	claimString, ok := gotClaim.(string)
	if !ok {
		return "", fmt.Errorf("'%s' claim is not a string", claim)
	}

	return claimString, nil
}

func (in *IDToken) StringSliceClaim(claim string) ([]string, error) {
	gotClaim, err := in.Claim(claim)
	if err != nil {
		return nil, err
	}

	// the claim is a slice of interfaces...
	claimValues, ok := gotClaim.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' claim is not a slice", claim)
	}

	// ...so we need to assert the actual type for each interface
	stringValues := make([]string, 0)

	for _, v := range claimValues {
		if str, ok := v.(string); ok {
			stringValues = append(stringValues, str)
		}
	}

	return stringValues, nil
}

func (in *IDToken) StringClaimOrEmpty(claim string) string {
	str, err := in.StringClaim(claim)
	if err != nil {
		return ""
	}

	return str
}

func (in *IDToken) StringSliceClaimOrEmpty(claim string) []string {
	s, err := in.StringSliceClaim(claim)
	if err != nil {
		return make([]string, 0)
	}

	return s
}

func (in *IDToken) TimeClaim(claim string) time.Time {
	gotClaim, err := in.Claim(claim)
	if err != nil {
		return time.Time{}
	}

	// jwx uses encoding/json for unmarshaling - JSON numbers are stored as float64
	claimTime, ok := gotClaim.(float64)
	if !ok {
		return time.Time{}
	}

	// time claims are NumericDate, which is the number of seconds since Epoch.
	return time.Unix(int64(claimTime), 0)
}

// ValidateRefreshedIDToken validates a refreshed id_token against the previous one, as per OpenID Connect Core, section 12.2
func ValidateRefreshedIDToken(cfg openidconfig.Config, previous, refreshed, expectedAcr string, jwks *jwk.Set) error {
	previousToken, err := ParseIDToken(previous)
	if err != nil {
		return fmt.Errorf("parsing previous id_token: %w", err)
	}

	refreshedToken, err := ParseIDToken(refreshed)
	if err != nil {
		return fmt.Errorf("parsing current id_token: %w", err)
	}

	// its iss Claim Value MUST be the same as in the ID Token issued when the original authentication occurred
	previousIssuer, ok := previousToken.Issuer()
	if !ok {
		return fmt.Errorf("missing required 'iss' claim in previous id_token")
	}
	refreshedIssuer, ok := refreshedToken.Issuer()
	if !ok {
		return fmt.Errorf("missing required 'iss' claim in refreshed id_token")
	}
	if previousIssuer != refreshedIssuer {
		return fmt.Errorf("'iss' claim mismatch, expected %q, got %q", previousIssuer, refreshedIssuer)
	}

	// its sub Claim Value MUST be the same as in the ID Token issued when the original authentication occurred
	previousSubject, ok := previousToken.Subject()
	if !ok {
		return fmt.Errorf("missing required 'sub' claim in previous id_token")
	}
	refreshedSubject, ok := refreshedToken.Subject()
	if !ok {
		return fmt.Errorf("missing required 'sub' claim in refreshed id_token")
	}
	if previousSubject != refreshedSubject {
		return fmt.Errorf("'sub' claim mismatch, expected %q, got %q", previousSubject, refreshedSubject)
	}

	// its iat Claim MUST represent the time that the new ID Token is issued
	previousIat, ok := previousToken.IssuedAt()
	if !ok {
		return fmt.Errorf("missing required 'iat' claim in previous id_token")
	}
	refreshedIat, ok := refreshedToken.IssuedAt()
	if !ok {
		return fmt.Errorf("missing required 'iat' claim in refreshed id_token")
	}
	if refreshedIat.Equal(previousIat) || refreshedIat.Before(previousIat) {
		return fmt.Errorf("'iat' claim in refreshed id_token must be greater than previous id_token, expected > %q, got %q", previousIat, refreshedIat)
	}

	// its aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred
	previousAudience, ok := previousToken.Audience()
	if !ok {
		return fmt.Errorf("missing required 'aud' claim in previous id_token")
	}
	refreshedAudience, ok := refreshedToken.Audience()
	if !ok {
		return fmt.Errorf("missing required 'aud' claim in refreshed id_token")
	}
	slices.Sort(previousAudience)
	slices.Sort(refreshedAudience)
	if !slices.Equal(previousAudience, refreshedAudience) {
		return fmt.Errorf("'aud' claim mismatch, expected %q, got %q", previousAudience, refreshedAudience)
	}

	// if the ID Token contains an auth_time Claim, its value MUST represent the time of the original authentication - not the time that the new ID token is issued
	if refreshedAuthTime := refreshedToken.AuthTime(); !refreshedAuthTime.IsZero() {
		previousAuthTime := previousToken.AuthTime()
		if !refreshedAuthTime.Equal(previousAuthTime) {
			return fmt.Errorf("'auth_time' claim mismatch, expected %q, got %q", previousAuthTime, refreshedAuthTime)
		}
	}

	// it SHOULD NOT have a nonce Claim, even when the ID Token issued at the time of the original authentication contained nonce;
	// however, if it is present, its value MUST be the same as in the ID Token issued at the time of the original authentication
	refreshedNonce := refreshedToken.StringClaimOrEmpty("nonce")
	if refreshedNonce != "" {
		previousNonce := previousToken.StringClaimOrEmpty("nonce")
		if previousNonce != refreshedNonce {
			return fmt.Errorf("'nonce' claim mismatch, expected %q, got %q", previousNonce, refreshedNonce)
		}
	}

	// otherwise, the same rules apply as apply when issuing an ID Token at the time of the original authentication
	return refreshedToken.Validate(cfg, expectedAcr, refreshedNonce, jwks)
}
