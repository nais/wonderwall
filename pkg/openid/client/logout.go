package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type Logout struct {
	*Client
	Cookie     *openid.LogoutCookie
	LogoutHint string

	callbackURL string
}

func NewLogout(c *Client, r *http.Request) (*Logout, error) {
	callbackURL, err := urlpkg.LogoutCallback(r)
	if err != nil {
		return nil, fmt.Errorf("generating logout callback url: %w", err)
	}

	state, err := crypto.Text(32)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	logoutCookie := &openid.LogoutCookie{
		State: state,
	}

	return &Logout{
		Client:      c,
		Cookie:      logoutCookie,
		LogoutHint:  r.URL.Query().Get("logout_hint"),
		callbackURL: callbackURL,
	}, nil
}

func (in *Logout) SingleLogoutURL(idToken string) string {
	endSessionEndpoint := in.cfg.Provider().EndSessionEndpointURL()
	v := endSessionEndpoint.Query()
	v.Set("post_logout_redirect_uri", in.callbackURL)
	v.Set("state", in.Cookie.State)

	if len(idToken) > 0 {
		v.Set("id_token_hint", idToken)
	}
	if len(in.LogoutHint) > 0 {
		v.Set("logout_hint", in.LogoutHint)
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
