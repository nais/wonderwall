package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/nais/liberator/pkg/keygen"
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

// Generate an initialization vector for encryption.
// It consists of the current UNIX timestamp with nanoseconds, and four bytes of randomness.
func IV() ([]byte, error) {
	stor := make([]byte, 0)
	buf := bytes.NewBuffer(stor)

	err := binary.Write(buf, binary.BigEndian, time.Now().UnixNano())
	if err != nil {
		return nil, err
	}

	// Pad nonce with 4 bytes
	random, err := keygen.Keygen(4)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, random)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Encrypts a plaintext with AES-256-GCM.
// Returns 12 bytes of IV, and then N bytes of ciphertext.
func (c *crypter) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := IV()
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

// Decrypts a ciphertext encrypted with AES-256-GCM.
// The first 12 bytes of the ciphertext is assumed to be the IV.
func (c *crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= 12 {
		return nil, fmt.Errorf("string is too short")
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
}
