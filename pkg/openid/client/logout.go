package client

import (
	"fmt"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/strings"
)

type Logout interface {
	CanonicalRedirect() string
	Cookie() *openid.LogoutCookie
	SingleLogoutURL(idToken string) string
}

type logout struct {
	Client
	cookie             *openid.LogoutCookie
	endSessionEndpoint *url.URL
}

func NewLogout(c Client) (Logout, error) {
	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	cookie := &openid.LogoutCookie{
		State:      state,
		RedirectTo: c.config().Client().GetPostLogoutRedirectURI(),
	}

	endSessionEndpoint, err := url.Parse(c.config().Provider().EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing end session endpoint: %w", err)
	}

	return &logout{
		Client:             c,
		cookie:             cookie,
		endSessionEndpoint: endSessionEndpoint,
	}, nil
}

func (in logout) CanonicalRedirect() string {
	return in.cookie.RedirectTo
}

func (in logout) Cookie() *openid.LogoutCookie {
	return in.cookie
}

func (in logout) SingleLogoutURL(idToken string) string {
	v := in.endSessionEndpoint.Query()
	v.Add("post_logout_redirect_uri", in.config().Client().GetLogoutCallbackURI())
	v.Add("state", in.cookie.State)

	if len(idToken) > 0 {
		v.Add("id_token_hint", idToken)
	}

	in.endSessionEndpoint.RawQuery = v.Encode()
	return in.endSessionEndpoint.String()
}
