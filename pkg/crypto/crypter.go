package crypto

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/nais/liberator/pkg/keygen"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nais/wonderwall/pkg/config"
)

const (
	KeySize = chacha20poly1305.KeySize

	// MaxPlaintextSize is set to 64 MB, which is a fairly generous limit. The implementation in x/crypto/xchacha20poly1305 has a plaintext limit to 256 GB.
	// We generally only handle data that is stored within a cookie or a session store, i.e. it should be reasonably small.
	// In most cases the data is around 4 KB or less, mostly depending on the length of the tokens returned from the identity provider.
	MaxPlaintextSize = 64 * 1024 * 1024
)

type crypter struct {
	key []byte
}

type Crypter interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

func NewCrypter(key []byte) Crypter {
	return &crypter{
		key: key,
	}
}

func EncryptionKeyOrGenerate(cfg *config.Config) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(cfg.EncryptionKey)
	if err != nil {
		if len(cfg.EncryptionKey) > 0 {
			return nil, fmt.Errorf("decode encryption key: %w", err)
		}
	}

	if len(key) == 0 {
		key, err = keygen.Keygen(KeySize)
		if err != nil {
			return nil, fmt.Errorf("generate random encryption key: %w", err)
		}
	}

	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("bad key length (expected %d, got %d)", chacha20poly1305.KeySize, len(key))
	}

	return key, nil
}

// Encrypt encrypts a plaintext with XChaCha20-Poly1305.
func (c *crypter) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, err
	}

	plaintextSize := len(plaintext)
	if plaintextSize > MaxPlaintextSize {
		return nil, fmt.Errorf("crypter: plaintext too large (%d > %d)", plaintextSize, MaxPlaintextSize)
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+plaintextSize+aead.Overhead())
	_, err = cryptorand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts a ciphertext encrypted with XChaCha20-Poly1305.
func (c *crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	// Split nonce and ciphertext.
	nonce, encrypted := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, encrypted, nil)
}
