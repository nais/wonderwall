package openid

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func ClientAssertion(provider Provider, expiration time.Duration) (string, error) {
	clientCfg := provider.GetClientConfiguration()
	key := clientCfg.GetClientJWK()

	iat := time.Now()
	exp := iat.Add(expiration)

	errs := make([]error, 0)

	tok := jwt.New()
	errs = append(errs, tok.Set(jwt.IssuerKey, clientCfg.GetClientID()))
	errs = append(errs, tok.Set(jwt.SubjectKey, clientCfg.GetClientID()))
	errs = append(errs, tok.Set(jwt.AudienceKey, provider.GetOpenIDConfiguration().Issuer))
	errs = append(errs, tok.Set("scope", clientCfg.GetScopes().String()))
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
