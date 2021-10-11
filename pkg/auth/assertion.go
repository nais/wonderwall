package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/token"
)

func ClientAssertion(cfg config.IDPorten, expiration time.Duration) (string, error) {
	key, err := jwk.ParseKey([]byte(cfg.ClientJWK))
	if err != nil {
		return "", fmt.Errorf("parsing client JWK: %w", err)
	}

	iat := time.Now()
	exp := iat.Add(expiration)

	errs := make([]error, 0)

	tok := jwt.New()
	errs = append(errs, tok.Set(jwt.IssuerKey, cfg.ClientID))
	errs = append(errs, tok.Set(jwt.SubjectKey, cfg.ClientID))
	errs = append(errs, tok.Set(jwt.AudienceKey, cfg.WellKnown.Issuer))
	errs = append(errs, tok.Set("scope", token.ScopeOpenID))
	errs = append(errs, tok.Set(jwt.IssuedAtKey, iat))
	errs = append(errs, tok.Set(jwt.ExpirationKey, exp))
	errs = append(errs, tok.Set(jwt.JwtIDKey, uuid.New().String()))

	for _, err := range errs {
		if err != nil {
			return "", fmt.Errorf("setting claim for client assertion: %w", err)
		}
	}

	encoded, err := jwt.Sign(tok, jwa.SignatureAlgorithm(key.Algorithm()), key)
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	return string(encoded), nil
}
