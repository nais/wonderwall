package openid

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

type IDToken struct {
	TokenType string
	Raw       string
	Token     jwt.Token
}

var _ Token = &IDToken{}

func ParseIDToken(jwks jwk.Set, token *oauth2.Token) (Token, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(jwks),
		jwt.InferAlgorithmFromKey(true),
	}
	idToken, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	result := &IDToken{
		TokenType: "IDtoken",
		Raw:       raw,
		Token:     idToken,
	}

	return result, nil
}

func (in *IDToken) Validate(opts ...jwt.ValidateOption) error {
	err := jwt.Validate(in.Token, opts...)
	if err != nil {
		return fmt.Errorf("validating id_token: %w", err)
	}

	return nil
}

func (in *IDToken) GetStringClaim(claim string) (string, error) {
	gotClaim, ok := in.Token.Get(claim)
	if !ok {
		return "", fmt.Errorf("missing required '%s' claim in id_token", claim)
	}

	claimString, ok := gotClaim.(string)
	if !ok {
		return "", fmt.Errorf("'%s' claim is not a string", claim)
	}

	return claimString, nil
}

func (in *IDToken) GetRaw() string {
	return in.Raw
}

func (in *IDToken) GetTokenType() string {
	return in.TokenType
}

func (in *IDToken) GetToken() jwt.Token {
	return in.Token
}
