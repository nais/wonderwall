package jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

type IDToken struct {
	Token
}

func (in *IDToken) GetSidClaim() (string, error) {
	return in.GetStringClaim(SidClaim)
}

func (in *IDToken) Validate(cfg openidconfig.Config, nonce string) error {
	openIDconfig := cfg.Provider()
	clientConfig := cfg.Client()

	opts := []jwt.ValidateOption{
		jwt.WithAudience(clientConfig.GetClientID()),
		jwt.WithClaimValue("nonce", nonce),
		jwt.WithIssuer(openIDconfig.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	if openIDconfig.SidClaimRequired() {
		opts = append(opts, jwt.WithRequiredClaim("sid"))
	}

	if len(clientConfig.GetACRValues()) > 0 {
		opts = append(opts, jwt.WithRequiredClaim("acr"))
	}

	return jwt.Validate(in.GetToken(), opts...)
}

func NewIDToken(raw string, jwtToken jwt.Token) *IDToken {
	return &IDToken{
		NewToken(raw, jwtToken),
	}
}

func ParseIDToken(raw string, jwks jwk.Set) (*IDToken, error) {
	idToken, err := Parse(raw, jwks)
	if err != nil {
		return nil, err
	}

	return NewIDToken(raw, idToken), nil
}
