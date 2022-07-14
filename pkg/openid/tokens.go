package openid

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/jwt"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

type Tokens struct {
	AccessToken  string
	Expiry       time.Time
	IDToken      *IDToken
	RefreshToken string
	TokenType    string
}

func NewTokens(src *oauth2.Token, jwks jwk.Set) (*Tokens, error) {
	idToken, err := ParseIDTokenFrom(src, jwks)
	if err != nil {
		return nil, fmt.Errorf("parsing id_token: %w", err)
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

func (in *IDToken) GetSidClaim() (string, error) {
	return in.GetStringClaim(jwt.SidClaim)
}

func (in *IDToken) Validate(cfg openidconfig.Config, nonce string) error {
	openIDconfig := cfg.Provider()
	clientConfig := cfg.Client()

	opts := []jwtlib.ValidateOption{
		jwtlib.WithAudience(clientConfig.GetClientID()),
		jwtlib.WithClaimValue("nonce", nonce),
		jwtlib.WithIssuer(openIDconfig.Issuer),
		jwtlib.WithAcceptableSkew(5 * time.Second),
	}

	if openIDconfig.SidClaimRequired() {
		opts = append(opts, jwtlib.WithRequiredClaim("sid"))
	}

	if len(clientConfig.GetACRValues()) > 0 {
		opts = append(opts, jwtlib.WithRequiredClaim("acr"))
	}

	return jwtlib.Validate(in.GetToken(), opts...)
}

func NewIDToken(raw string, jwtToken jwtlib.Token) *IDToken {
	return &IDToken{
		jwt.NewToken(raw, jwtToken),
	}
}

func ParseIDToken(raw string, jwks jwk.Set) (*IDToken, error) {
	idToken, err := jwt.Parse(raw, jwks)
	if err != nil {
		return nil, err
	}

	return NewIDToken(raw, idToken), nil
}

func ParseIDTokenFrom(tokens *oauth2.Token, jwks jwk.Set) (*IDToken, error) {
	idToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	return ParseIDToken(idToken, jwks)
}
