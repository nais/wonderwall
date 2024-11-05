package jwt

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	AcrClaim      = "acr"
	AmrClaim      = "amr"
	AuthTimeClaim = "auth_time"
	LocaleClaim   = "locale"
	SidClaim      = "sid"
	OidClaim      = "oid"
)

type Token struct {
	serialized string
	token      jwt.Token
}

func (in *Token) GetClaim(claim string) (any, error) {
	if in.token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	gotClaim, ok := in.token.Get(claim)
	if !ok {
		return nil, fmt.Errorf("missing required '%s' claim in id_token", claim)
	}

	return gotClaim, nil
}

func (in *Token) GetExpiration() time.Time {
	return in.token.Expiration()
}

func (in *Token) GetSerialized() string {
	return in.serialized
}

func (in *Token) GetStringClaim(claim string) (string, error) {
	gotClaim, err := in.GetClaim(claim)
	if err != nil {
		return "", err
	}

	claimString, ok := gotClaim.(string)
	if !ok {
		return "", fmt.Errorf("'%s' claim is not a string", claim)
	}

	return claimString, nil
}

func (in *Token) GetStringSliceClaim(claim string) ([]string, error) {
	gotClaim, err := in.GetClaim(claim)
	if err != nil {
		return nil, err
	}

	// the claim is a slice of interfaces...
	claimValues, ok := gotClaim.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' claim is not a slice", claim)
	}

	// ...so we need to assert the actual type for each interface
	strings := make([]string, 0)

	for _, v := range claimValues {
		if str, ok := v.(string); ok {
			strings = append(strings, str)
		}
	}

	return strings, nil
}

func (in *Token) GetStringClaimOrEmpty(claim string) string {
	str, err := in.GetStringClaim(claim)
	if err != nil {
		return ""
	}

	return str
}

func (in *Token) GetStringSliceClaimOrEmpty(claim string) []string {
	s, err := in.GetStringSliceClaim(claim)
	if err != nil {
		return make([]string, 0)
	}

	return s
}

func (in *Token) GetTimeClaim(claim string) time.Time {
	gotClaim, err := in.GetClaim(claim)
	if err != nil {
		return time.Time{}
	}

	// jwx uses encoding/json for unmarshaling - JSON numbers are stored as float64
	claimTime, ok := gotClaim.(float64)
	if !ok {
		return time.Time{}
	}

	// time claims are NumericDate, which is the number of seconds since Epoch.
	return time.Unix(int64(claimTime), 0)
}

func (in *Token) GetToken() jwt.Token {
	return in.token
}

func NewToken(raw string, jwtToken jwt.Token) Token {
	return Token{
		serialized: raw,
		token:      jwtToken,
	}
}
