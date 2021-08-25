package keyset

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// EnsureValid sets fields for the keys in the given keyset if missing.
// We only accept keys with the "alg" value set to RS256.
func EnsureValid(ctx context.Context, jwks jwk.Set) error {
	for iter := jwks.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		if len(key.Algorithm()) == 0 {
			err := key.Set(jwk.AlgorithmKey, jwa.RS256)
			if err != nil {
				return fmt.Errorf("setting key algorithm")
			}
		}

		if key.Algorithm() != string(jwa.RS256) {
			jwks.Remove(key)
		}
	}
	return nil
}
