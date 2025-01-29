package openid

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/cookie"
)

type LoginCookie struct {
	Acr          string `json:"acr"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
	RedirectURI  string `json:"redirect_uri"`
	Referer      string `json:"referer"`
	State        string `json:"state"`
}

type LogoutCookie struct {
	State      string `json:"state"`
	RedirectTo string `json:"redirect_to"`
}

func GetLoginCookie(r *http.Request, crypter crypto.Crypter) (*LoginCookie, error) {
	loginCookieJson, err := cookie.GetDecrypted(r, cookie.Login, crypter)
	if err != nil {
		return nil, err
	}

	var loginCookie LoginCookie
	err = json.Unmarshal([]byte(loginCookieJson), &loginCookie)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling: %w", err)
	}

	return &loginCookie, nil
}

func GetLogoutCookie(r *http.Request, crypter crypto.Crypter) (*LogoutCookie, error) {
	logoutCookieJson, err := cookie.GetDecrypted(r, cookie.Logout, crypter)
	if err != nil {
		return nil, err
	}

	var logoutCookie LogoutCookie
	err = json.Unmarshal([]byte(logoutCookieJson), &logoutCookie)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling: %w", err)
	}

	return &logoutCookie, nil
}
