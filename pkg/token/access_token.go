package token

import (
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

type AccessToken struct {
	Raw   string
	Token jwt.Token
	Type  Type
}

func (in *AccessToken) GetJtiClaim() string {
	return GetStringClaimOrEmpty(in.Token, JtiClaim)
}

func (in *AccessToken) GetStringClaim(claim string) (string, error) {
	return GetStringClaim(in.Token, claim)
}

func NewAccessToken(raw string, token jwt.Token) *AccessToken {
	return &AccessToken{
		Raw:   raw,
		Token: token,
		Type:  TypeAccessToken,
	}
}

func ParseAccessToken(tokens *oauth2.Token, jwks jwk.Set) (*AccessToken, error) {
	accessToken, err := ParseJwt(tokens.AccessToken, jwks)
	if err != nil {
		return nil, err
	}

	return NewAccessToken(tokens.AccessToken, accessToken), nil
}
