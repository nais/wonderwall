package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JwkSet struct {
	Private jwk.Set
	Public  jwk.Set
}

func NewJwk() (jwk.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("importing key: %w", err)
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256().String())
	if err != nil {
		return nil, fmt.Errorf("setting algorithm: %w", err)
	}

	err = key.Set(jwk.KeyTypeKey, jwa.RSA().String())
	if err != nil {
		return nil, fmt.Errorf("setting key type: %w", err)
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		return nil, fmt.Errorf("assigning key id: %w", err)
	}

	return key, nil
}

func NewJwkSet() (*JwkSet, error) {
	key, err := NewJwk()
	if err != nil {
		return nil, fmt.Errorf("creating jwk: %w", err)
	}

	privateKeys := jwk.NewSet()
	err = privateKeys.AddKey(key)
	if err != nil {
		return nil, fmt.Errorf("adding key to set: %w", err)
	}

	publicKeys, err := jwk.PublicSetOf(privateKeys)
	if err != nil {
		return nil, fmt.Errorf("creating public set: %w", err)
	}

	return &JwkSet{
		Private: privateKeys,
		Public:  publicKeys,
	}, nil
}
