package jwt

import (
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type RefreshToken struct {
	Token
}

func NewRefreshTokenToken(raw string, jwtToken jwt.Token) *RefreshToken {
	return &RefreshToken{
		NewToken(raw, jwtToken),
	}
}

func ParseRefreshTokenToken(raw string, jwks jwk.Set) (*RefreshToken, error) {
	refreshToken, err := Parse(raw, jwks)
	if err != nil {
		return nil, err
	}

	return NewRefreshTokenToken(raw, refreshToken), nil
}
