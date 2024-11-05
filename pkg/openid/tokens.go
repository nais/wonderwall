package openid

import (
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/openid/acr"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
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

	if err := idToken.Validate(cfg, cookie, jwks); err != nil {
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

type IDToken struct {
	jwt.Token
}

func (in *IDToken) GetAcrClaim() string {
	return in.GetStringClaimOrEmpty(jwt.AcrClaim)
}

func (in *IDToken) GetAmrClaim() string {
	s := in.GetStringClaimOrEmpty(jwt.AmrClaim)
	if len(s) == 0 {
		s = strings.Join(in.GetStringSliceClaimOrEmpty(jwt.AmrClaim), ",")
	}

	return s
}

func (in *IDToken) GetAuthTimeClaim() time.Time {
	return in.GetTimeClaim(jwt.AuthTimeClaim)
}

func (in *IDToken) GetLocaleClaim() string {
	return in.GetStringClaimOrEmpty(jwt.LocaleClaim)
}

func (in *IDToken) GetOidClaim() string {
	return in.GetStringClaimOrEmpty(jwt.OidClaim)
}

func (in *IDToken) GetSidClaim() (string, error) {
	return in.GetStringClaim(jwt.SidClaim)
}

func (in *IDToken) Validate(cfg openidconfig.Config, cookie *LoginCookie, jwks *jwk.Set) error {
	openIDconfig := cfg.Provider()
	clientConfig := cfg.Client()

	_, err := jws.Verify([]byte(in.GetSerialized()), jws.WithKeySet(*jwks))
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	opts := []jwtlib.ValidateOption{
		// OpenID Connect Core, section 2 - required claims.
		jwtlib.WithRequiredClaim("iss"),
		jwtlib.WithRequiredClaim("sub"),
		jwtlib.WithRequiredClaim("aud"),
		jwtlib.WithRequiredClaim("exp"),
		jwtlib.WithRequiredClaim("iat"),
		// OpenID Connect Core section 3.1.3.7, step 2.
		//  The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the `iss` (issuer) Claim.
		jwtlib.WithIssuer(openIDconfig.Issuer()),
		// OpenID Connect Core section 3.1.3.7, step 3.
		//  The Client MUST validate that the `aud` (audience) Claim contains its `client_id` value registered at the Issuer identified by the `iss` (issuer) Claim as an audience.
		//  The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience
		jwtlib.WithAudience(clientConfig.ClientID()),
		// OpenID Connect Core section 3.1.3.7, step 11.
		//  If a nonce value was sent in the Authentication Request, a `nonce` Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request.
		jwtlib.WithClaimValue("nonce", cookie.Nonce),
		// Skew tolerance for time-based claims (exp, iat, nbf)
		jwtlib.WithAcceptableSkew(5 * time.Second),
	}

	if openIDconfig.SidClaimRequired() {
		opts = append(opts, jwtlib.WithRequiredClaim(jwt.SidClaim))
	}

	// OpenID Connect Core 3.1.3.7, step 12.
	//  If the `acr` Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
	if len(clientConfig.ACRValues()) > 0 {
		opts = append(opts, jwtlib.WithRequiredClaim(jwt.AcrClaim))

		if len(cookie.Acr) > 0 {
			actual := in.GetAcrClaim()
			expected := cookie.Acr

			err := acr.Validate(expected, actual)
			if err != nil {
				return err
			}
		}
	}

	if err := jwtlib.Validate(in.GetToken(), opts...); err != nil {
		return err
	}

	// OpenID Connect Core 3.1.3.7, step 3.
	//  The `aud` (audience) Claim MAY contain an array with more than one element.
	//  The ID Token MUST be rejected if the ID Token [...] contains additional audiences not trusted by the Client.
	audiences := in.GetToken().Audience()
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

func NewIDToken(raw string, jwtToken jwtlib.Token) *IDToken {
	return &IDToken{
		jwt.NewToken(raw, jwtToken),
	}
}

// ParseIDToken parses a raw ID token string into an IDToken struct.
// It does not validate the token nor verify the signature.
func ParseIDToken(raw string) (*IDToken, error) {
	opts := []jwtlib.ParseOption{
		jwtlib.WithValidate(false), // JWT validation is done in IDToken.Validate
		jwtlib.WithVerify(false),   // Signature verification is done in IDToken.Validate
	}
	idToken, err := jwtlib.ParseString(raw, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	return NewIDToken(raw, idToken), nil
}
