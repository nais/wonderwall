package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func ValidateIdToken(ctx context.Context, verifier *oidc.IDTokenVerifier, token *oauth2.Token, nonce string) (*oidc.IDToken, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce does not match")
	}

	return idToken, nil
}
