package session

import (
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/strings"
)

// ExternalID returns the external session ID, derived from the given request or id_token; e.g. `sid` or `session_state`.
// If none are present, a generated ID is returned.
func ExternalID(r *http.Request, cfg openidconfig.Provider, idToken *openid.IDToken) (string, error) {
	// 1. check for 'sid' claim in id_token
	sessionID, err := idToken.Sid()
	if err == nil {
		return sessionID, nil
	}
	// 1a. error if sid claim is required according to openid config
	if err != nil && cfg.SidClaimRequired() {
		return "", err
	}

	// 2. check for session_state in callback params
	sessionID, err = getSessionStateFrom(r)
	if err == nil {
		return sessionID, nil
	}
	// 2a. error if session_state is required according to openid config
	if err != nil && cfg.SessionStateRequired() {
		return "", err
	}

	// 3. generate ID if all else fails
	sessionID, err = strings.GenerateBase64(64)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return sessionID, nil
}

func getSessionStateFrom(r *http.Request) (string, error) {
	params := r.URL.Query()

	sessionState := params.Get("session_state")
	if len(sessionState) == 0 {
		return "", fmt.Errorf("missing required 'session_state' in params")
	}
	return sessionState, nil
}
