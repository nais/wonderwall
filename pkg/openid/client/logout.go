package client

import (
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/openid"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type Logout struct {
	*Client
	request           *http.Request
	logoutCallbackURL string
}

func NewLogout(c *Client, r *http.Request) (*Logout, error) {
	logoutCallbackURL, err := urlpkg.LogoutCallback(r)
	if err != nil {
		return nil, fmt.Errorf("generating logout callback url: %w", err)
	}

	return &Logout{
		Client:            c,
		logoutCallbackURL: logoutCallbackURL,
		request:           r,
	}, nil
}

func (in *Logout) SingleLogoutURL(idToken string) string {
	endSessionEndpoint := in.cfg.Provider().EndSessionEndpointURL()
	v := endSessionEndpoint.Query()
	v.Add(openid.PostLogoutRedirectURI, in.logoutCallbackURL)

	if len(idToken) > 0 {
		v.Add(openid.IDTokenHint, idToken)
	}

	endSessionEndpoint.RawQuery = v.Encode()
	return endSessionEndpoint.String()
}
