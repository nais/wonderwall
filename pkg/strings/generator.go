package strings

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateBase64 generates a random string of a given length, and base64 URI-encodes it.
func GenerateBase64(length int) (string, error) {
	bytes, err := Generate(length)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Generate generates a random byte array of a given length.
func Generate(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("reading rand.Reader: %w", err)
	}

	return bytes, nil
}
