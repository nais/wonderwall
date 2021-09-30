package token

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/keyset"
)

const ScopeOpenID = "openid"

type JWTTokenRequest struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Scopes    string `json:"scope"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JwtID     string `json:"jti"`
}

type IDToken struct {
	Raw   string
	Token jwt.Token
}

func (in *IDToken) Validate(opts ...jwt.ValidateOption) error {
	err := jwt.Validate(in.Token, opts...)
	if err != nil {
		return fmt.Errorf("validating id_token: %w", err)
	}

	return nil
}

func (in *IDToken) GetSID() (string, bool) {
	sid, ok := in.Token.Get("sid")
	return sid.(string), ok
}

func ParseIDToken(ctx context.Context, jwks jwk.Set, token *oauth2.Token) (*IDToken, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	err := keyset.EnsureValid(ctx, jwks)
	if err != nil {
		return nil, err
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(jwks),
	}
	idToken, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	result := &IDToken{
		Raw:   raw,
		Token: idToken,
	}

	return result, nil
}
