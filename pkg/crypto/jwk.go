package crypto

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

func NewJwk() (jwk.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		return nil, err
	}

	key.Set(jwk.AlgorithmKey, jwa.RS256)
	key.Set(jwk.KeyTypeKey, jwa.RSA)
	jwk.AssignKeyID(key)

	return key, nil
}
