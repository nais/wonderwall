package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func ValidateIdToken(ctx context.Context, verifier *oidc.IDTokenVerifier, token *oauth2.Token, nonce string) error {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("missing id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return err
	}

	if idToken.Nonce != nonce {
		return fmt.Errorf("nonce does not match")
	}

	return nil
}
