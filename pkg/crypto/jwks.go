package crypto

import (
	"github.com/lestrrat-go/jwx/jwk"
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
	privateKeys.Add(key)

	publicKeys, err := jwk.PublicSetOf(privateKeys)
	if err != nil {
		return nil, err
	}

	return &JwkSet{
		Private: privateKeys,
		Public:  publicKeys,
	}, nil
}
