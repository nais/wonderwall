package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

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

func GetStringClaim(token jwt.Token, claim string) (string, error) {
	if token == nil {
		return "", fmt.Errorf("token is nil")
	}

	gotClaim, ok := token.Get(claim)
	if !ok {
		return "", fmt.Errorf("missing required '%s' claim in id_token", claim)
	}

	claimString, ok := gotClaim.(string)
	if !ok {
		return "", fmt.Errorf("'%s' claim is not a string", claim)
	}

	return claimString, nil
}

func GetStringClaimOrEmpty(token jwt.Token, claim string) string {
	str, err := GetStringClaim(token, claim)
	if err != nil {
		return ""
	}

	return str
}
