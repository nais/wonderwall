package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

type Tokens struct {
	IDToken     *IDToken
	AccessToken *AccessToken
}

func (in *Tokens) JwtIDs() IDs {
	return IDs{
		IDToken:     in.IDToken.GetJtiClaim(),
		AccessToken: in.AccessToken.GetJtiClaim(),
	}
}

func NewTokens(idToken *IDToken, accessToken *AccessToken) *Tokens {
	return &Tokens{
		IDToken:     idToken,
		AccessToken: accessToken,
	}
}

func ParseOauth2Token(tokens *oauth2.Token, jwks jwk.Set) (*Tokens, error) {
	idToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	return ParseTokensFromStrings(idToken, tokens.AccessToken, jwks)
}

func ParseTokensFromStrings(idToken, accessToken string, jwks jwk.Set) (*Tokens, error) {
	parsedIdToken, err := ParseIDToken(idToken, jwks)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}

	parsedAccessToken, err := ParseAccessToken(accessToken, jwks)
	if err != nil {
		return nil, fmt.Errorf("access_token: %w", err)
	}

	return NewTokens(parsedIdToken, parsedAccessToken), nil
}
