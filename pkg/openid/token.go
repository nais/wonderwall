package openid

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

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

func (in *IDToken) GetSID() (string, error) {
	sid, ok := in.Token.Get("sid")
	if !ok {
		return "", fmt.Errorf("missing required 'sid' claim in id_token")
	}

	sidString, ok := sid.(string)
	if !ok {
		return "", fmt.Errorf("'sid' claim is not a string")
	}

	return sidString, nil
}

func ParseIDToken(jwks jwk.Set, token *oauth2.Token) (*IDToken, error) {
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
		Raw:   raw,
		Token: idToken,
	}

	return result, nil
}
