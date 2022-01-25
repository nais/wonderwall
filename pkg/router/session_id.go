package router

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid"
)

const (
	SessionStateParamKey = "session_state"
)

func SessionID(cfg *openid.Configuration, idToken *openid.IDToken, params url.Values) (string, error) {
	var sessionID string
	var err error

	switch {
	case cfg.SidClaimRequired():
		sessionID, err = idToken.GetStringClaim("sid")
	case cfg.SessionStateRequired():
		sessionID, err = getSessionStateFrom(params)
	default:
		sessionID, err = generateSessionID()
	}

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
