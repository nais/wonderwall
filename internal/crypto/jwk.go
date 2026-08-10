package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	return NewJwkWithAlg(jwa.RS256())
}

func NewJwkWithAlg(alg jwa.SignatureAlgorithm) (jwk.Key, error) {
	var privateKey any
	var err error

	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case jwa.ES256():
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.ES384():
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jwa.ES512():
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	// EdDSA is deprecated by RFC 9864, but existing client JWKs still declare it.
	case jwa.EdDSAEd25519(), jwa.EdDSA():
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("importing key: %w", err)
	}

	err = key.Set(jwk.AlgorithmKey, alg.String())
	if err != nil {
		return nil, fmt.Errorf("setting algorithm: %w", err)
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
