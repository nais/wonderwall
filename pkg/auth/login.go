package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

type Parameters struct {
	CodeVerifier  string
	CodeChallenge string
	Nonce         string
	State         string
}

func GenerateLoginParameters() (*Parameters, error) {
	codeVerifier := make([]byte, 64)
	nonce := make([]byte, 32)
	state := make([]byte, 32)

	var err error

	_, err = io.ReadFull(rand.Reader, state)
	if err != nil {
		return nil, fmt.Errorf("failed to create state: %w", err)
	}

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	_, err = io.ReadFull(rand.Reader, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create code verifier: %w", err)
	}

	codeVerifier = []byte(base64.RawURLEncoding.EncodeToString(codeVerifier))
	hasher := sha256.New()
	hasher.Write(codeVerifier)
	codeVerifierHash := hasher.Sum(nil)

	return &Parameters{
		CodeVerifier:  string(codeVerifier),
		CodeChallenge: base64.RawURLEncoding.EncodeToString(codeVerifierHash),
		Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
		State:         base64.RawURLEncoding.EncodeToString(state),
	}, nil
}
