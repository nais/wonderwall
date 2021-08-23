package config

import (
	"encoding/json"
	"github.com/nais/wonderwall/pkg/token"
	"gopkg.in/square/go-jose.v2"
	"time"
)

func (cfg *IDPorten) SignedJWTProfileAssertion(expiration time.Duration) (string, error) {
	key := &jose.JSONWebKey{}
	err := json.Unmarshal([]byte(cfg.ClientJWK), key)
	if err != nil {
		return "", err
	}
	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	iat := time.Now()
	exp := iat.Add(expiration)
	jwtRequest := &token.JWTTokenRequest{
		Issuer:    cfg.ClientID,
		Subject:   cfg.ClientID,
		Audience:  cfg.WellKnown.Issuer,
		Scopes:    token.ScopeOpenID,
		ExpiresAt: exp.Unix(),
		IssuedAt:  iat.Unix(),
	}

	payload, err := json.Marshal(jwtRequest)
	if err != nil {
		return "", err
	}

	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return result.CompactSerialize()
}
