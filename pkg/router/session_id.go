package router

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/openid"
)

const (
	SessionStateParamKey = "session_state"
)

func NewSessionID(cfg *openid.Configuration, idToken *jwt.IDToken, params url.Values) (string, error) {
	// 1. check for 'sid' claim in id_token
	sessionID, err := idToken.GetSidClaim()
	if err == nil {
		return sessionID, nil
	}
	// 1a. error if sid claim is required according to openid config
	if err != nil && cfg.SidClaimRequired() {
		return "", err
	}

	// 2. check for session_state in callback params
	sessionID, err = getSessionStateFrom(params)
	if err == nil {
		return sessionID, nil
	}
	// 2a. error if session_state is required according to openid config
	if err != nil && cfg.SessionStateRequired() {
		return "", err
	}

	// 3. generate ID if all else fails
	sessionID, err = generateSessionID()
	if err != nil {
		return "", err
	}
	return sessionID, nil
}

func getSessionStateFrom(params url.Values) (string, error) {
	sessionState := params.Get(SessionStateParamKey)
	if len(sessionState) == 0 {
		return "", fmt.Errorf("missing required '%s' in params", SessionStateParamKey)
	}
	return sessionState, nil
}

func generateSessionID() (string, error) {
	rawID := make([]byte, 64)

	_, err := io.ReadFull(rand.Reader, rawID)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(rawID), nil
}
