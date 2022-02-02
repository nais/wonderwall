package token

import (
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
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

func ParseAccessToken(raw string, jwks jwk.Set) (*AccessToken, error) {
	accessToken, err := ParseJwt(raw, jwks)
	if err != nil {
		return nil, err
	}

	return NewAccessToken(raw, accessToken), nil
}
