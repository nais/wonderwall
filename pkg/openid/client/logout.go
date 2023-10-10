package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/strings"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type Logout struct {
	*Client
	Cookie            *openid.LogoutCookie
	logoutCallbackURL string
}

func NewLogout(c *Client, r *http.Request) (*Logout, error) {
	logoutCallbackURL, err := urlpkg.LogoutCallback(r)
	if err != nil {
		return nil, fmt.Errorf("generating logout callback url: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	logoutCookie := &openid.LogoutCookie{
		State: state,
	}

	return &Logout{
		Client:            c,
		Cookie:            logoutCookie,
		logoutCallbackURL: logoutCallbackURL,
	}, nil
}

func (in *Logout) SingleLogoutURL(idToken string) string {
	endSessionEndpoint := in.cfg.Provider().EndSessionEndpointURL()
	v := endSessionEndpoint.Query()
	v.Set("post_logout_redirect_uri", in.logoutCallbackURL)
	v.Set("state", in.Cookie.State)

	if len(idToken) > 0 {
		v.Set("id_token_hint", idToken)
	}

	endSessionEndpoint.RawQuery = v.Encode()
	return endSessionEndpoint.String()
}

func (in *Logout) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter, canonicalRedirect string) error {
	in.Cookie.RedirectTo = canonicalRedirect

	logoutCookieJson, err := json.Marshal(in.Cookie)
	if err != nil {
		return fmt.Errorf("marshalling logout cookie: %w", err)
	}

	value := string(logoutCookieJson)
	return cookie.EncryptAndSet(w, cookie.Logout, value, opts, crypter)
}
