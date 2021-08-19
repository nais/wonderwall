package cryptutil_test

import (
	"crypto/rand"
	"github.com/nais/naisplater/pkg/cryptutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	plaintext = []byte("foo bar, this is a very nice plaintext")
	key       = make([]byte, 32)
)

const (
	// Run this many iterations to make sure the IV is not re-used
	ivIterations = 50000
)

// Generate a new encryption key on every test run.
func init() {
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
}

// Test that encryption with a 256-bit key works,
// and that the ciphertext differs from one message to the next.
func TestEncrypt(t *testing.T) {
	var cur, prev []byte
	var err error

	for i := ivIterations; i != 0; i-- {
		cur, err = cryptutil.Encrypt(plaintext, key)
		assert.Nil(t, err)
		assert.NotNil(t, cur)
		assert.NotEqual(t, prev, cur, "IV re-used")
		prev = make([]byte, len(cur))
		copy(prev, cur)
	}
}

// Test that encrypted messages can be decrypted.
func TestDecrypt(t *testing.T) {
	ciphertext, err := cryptutil.Encrypt(plaintext, key)
	assert.Nil(t, err)

	decrypted, err := cryptutil.Decrypt(ciphertext, key)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func BenchmarkEncrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		cryptutil.Encrypt(plaintext, key)
	}
}
