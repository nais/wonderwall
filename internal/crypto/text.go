package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

// Text generates a cryptographically secure random string of a given length, and base64 URL-encodes it.
func Text(length int) (string, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(data), nil
}
