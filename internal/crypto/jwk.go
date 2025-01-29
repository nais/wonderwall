package crypto

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwkSet struct {
	Private jwk.Set
	Public  jwk.Set
}

func NewJwk() (jwk.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, err
	}

	key.Set(jwk.AlgorithmKey, jwa.RS256)
	key.Set(jwk.KeyTypeKey, jwa.RSA)
	jwk.AssignKeyID(key)

	return key, nil
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
