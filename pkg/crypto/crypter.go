package crypto

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/nais/liberator/pkg/keygen"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nais/wonderwall/pkg/config"
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
		key, err = keygen.Keygen(32)
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

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
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
