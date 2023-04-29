package openid

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/middleware"
)

type LoginCookie struct {
	Acr          string `json:"acr"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
	RedirectURI  string `json:"redirect_uri"`
	Referer      string `json:"referer"`
	State        string `json:"state"`
}

func GetLoginCookie(r *http.Request, crypter crypto.Crypter) (*LoginCookie, error) {
	loginCookieJson, err := cookie.GetDecrypted(r, cookie.Login, crypter)
	if err != nil {
		middleware.LogEntryFrom(r).Debugf("failed to fetch login cookie: %+v; falling back to legacy cookie", err)

		loginCookieJson, err = cookie.GetDecrypted(r, cookie.LoginLegacy, crypter)
		if err != nil {
			return nil, err
		}
	}

	var loginCookie LoginCookie
	err = json.Unmarshal([]byte(loginCookieJson), &loginCookie)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling: %w", err)
	}

	return &loginCookie, nil
}
