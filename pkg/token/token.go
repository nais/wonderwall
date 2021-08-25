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
}

type IDToken struct {
	Raw       string
	SessionID string
	Token     jwt.Token
}

func (in *IDToken) Validate(opts ...jwt.ValidateOption) error {
	err := jwt.Validate(in.Token, opts...)
	if err != nil {
		return fmt.Errorf("validating id_token: %w", err)
	}

	return nil
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
		jwt.WithRequiredClaim("sid"),
	}
	idToken, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	sessionID, ok := idToken.Get("sid")
	if !ok {
		return nil, fmt.Errorf("missing 'sid' claim in id_token")
	}

	result := &IDToken{
		Raw:       raw,
		SessionID: sessionID.(string),
		Token:     idToken,
	}

	return result, nil
}
