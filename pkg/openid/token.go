package openid

import (
	"github.com/lestrrat-go/jwx/jwt"
)

type Token interface {
	Validate(opts ...jwt.ValidateOption) error
	GetStringClaim(claim string) (string, error)
	GetRaw() string
	GetTokenType() string
	GetToken() jwt.Token
}
