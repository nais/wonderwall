package token

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

type Type int

const (
	TypeIDToken Type = iota
	TypeAccessToken
)

const (
	JtiClaim = "jti"
	SidClaim = "sid"
)

type Tokens struct {
	IDToken     *IDToken
	AccessToken *AccessToken
}

type JwtIDs struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

func ParseTokens(tokens *oauth2.Token, jwks jwk.Set) (*Tokens, error) {
	idToken, err := ParseIDToken(tokens, jwks)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}

	accessToken, err := ParseAccessToken(tokens, jwks)
	if err != nil {
		return nil, fmt.Errorf("access_token: %w", err)
	}

	return &Tokens{
		IDToken:     idToken,
		AccessToken: accessToken,
	}, nil
}

func (in *Tokens) JwtIDs() JwtIDs {
	return JwtIDs{
		IDToken:     in.IDToken.GetJtiClaim(),
		AccessToken: in.AccessToken.GetJtiClaim(),
	}
}

func ParseJwt(raw string, jwks jwk.Set) (jwt.Token, error) {
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
