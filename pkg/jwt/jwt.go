package jwt

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type Token interface {
	GetExpiration() time.Time
	GetJtiClaim() string
	GetSerialized() string
	GetStringClaim(claim string) (string, error)
	GetToken() jwt.Token
	GetUtiClaim() string
}

type token struct {
	serialized string
	token      jwt.Token
}

func (in *token) GetExpiration() time.Time {
	return in.token.Expiration()
}

func (in *token) GetJtiClaim() string {
	return in.GetStringClaimOrEmpty(JtiClaim)
}

func (in *token) GetSerialized() string {
	return in.serialized
}

func (in *token) GetStringClaim(claim string) (string, error) {
	if in.token == nil {
		return "", fmt.Errorf("token is nil")
	}

	gotClaim, ok := in.token.Get(claim)
	if !ok {
		return "", fmt.Errorf("missing required '%s' claim in id_token", claim)
	}

	claimString, ok := gotClaim.(string)
	if !ok {
		return "", fmt.Errorf("'%s' claim is not a string", claim)
	}

	return claimString, nil
}

func (in *token) GetStringClaimOrEmpty(claim string) string {
	str, err := in.GetStringClaim(claim)
	if err != nil {
		return ""
	}

	return str
}

func (in *token) GetToken() jwt.Token {
	return in.token
}

func (in *token) GetUtiClaim() string {
	return in.GetStringClaimOrEmpty(UtiClaim)
}

func NewToken(raw string, jwtToken jwt.Token) Token {
	return &token{
		serialized: raw,
		token:      jwtToken,
	}
}

func Parse(raw string, jwks jwk.Set) (jwt.Token, error) {
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(jwks),
		jwt.InferAlgorithmFromKey(true),
	}
	token, err := jwt.ParseString(raw, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	return token, nil
}
