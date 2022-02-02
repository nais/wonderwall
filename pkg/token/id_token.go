package token

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
)

type IDToken struct {
	Raw   string
	Token jwt.Token
	Type  Type
}

func (in *IDToken) GetJtiClaim() string {
	return GetStringClaimOrEmpty(in.Token, JtiClaim)
}

func (in *IDToken) GetSidClaim() (string, error) {
	return in.GetStringClaim(SidClaim)
}

func (in *IDToken) GetStringClaim(claim string) (string, error) {
	return GetStringClaim(in.Token, claim)
}

func (in *IDToken) Validate(provider openid.Provider, nonce string) error {
	openIDconfig := provider.GetOpenIDConfiguration()
	clientConfig := provider.GetClientConfiguration()

	opts := []jwt.ValidateOption{
		jwt.WithAudience(clientConfig.GetClientID()),
		jwt.WithClaimValue("nonce", nonce),
		jwt.WithIssuer(openIDconfig.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	if openIDconfig.SidClaimRequired() {
		opts = append(opts, jwt.WithRequiredClaim("sid"))
	}

	if len(clientConfig.GetACRValues()) > 0 {
		opts = append(opts, jwt.WithRequiredClaim("acr"))
	}

	return jwt.Validate(in.Token, opts...)
}

func NewIDToken(raw string, token jwt.Token) *IDToken {
	return &IDToken{
		Raw:   raw,
		Token: token,
		Type:  TypeIDToken,
	}
}

func ParseIDToken(tokens *oauth2.Token, jwks jwk.Set) (*IDToken, error) {
	raw, ok := tokens.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	idToken, err := ParseJwt(raw, jwks)
	if err != nil {
		return nil, err
	}

	return NewIDToken(raw, idToken), nil
}
