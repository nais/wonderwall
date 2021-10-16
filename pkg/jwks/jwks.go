package jwks

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type Pair struct {
	Private jwk.Set
	Public  jwk.Set
}

func NewJwksPair() (*Pair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		return nil, err
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		return nil, err
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	if err != nil {
		return nil, err
	}

	privateKeys := jwk.NewSet()
	privateKeys.Add(key)

	publicKeys, err := jwk.PublicSetOf(privateKeys)
	if err != nil {
		return nil, err
	}

	return &Pair{
		Private: privateKeys,
		Public:  publicKeys,
	}, nil
}
