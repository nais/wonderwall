package crypto

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwkSet struct {
	Private jwk.Set
	Public  jwk.Set
}

func NewJwkSet() (*JwkSet, error) {
	key, err := NewJwk()
	if err != nil {
		return nil, err
	}

	privateKeys := jwk.NewSet()
	privateKeys.AddKey(key)

	publicKeys, err := jwk.PublicSetOf(privateKeys)
	if err != nil {
		return nil, err
	}

	return &JwkSet{
		Private: privateKeys,
		Public:  publicKeys,
	}, nil
}
