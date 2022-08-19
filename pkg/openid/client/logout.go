package client

import (
	"fmt"
	"net/http"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/openid"
)

type Logout interface {
	SingleLogoutURL(idToken string) string
}

type logout struct {
	Client
	request           *http.Request
	logoutCallbackURL string
}

func NewLogout(c Client, r *http.Request) (Logout, error) {
	logoutCallbackURL, err := urlpkg.LogoutCallbackURL(r)
	if err != nil {
		return nil, fmt.Errorf("generating logout callback url: %w", err)
	}

	return &logout{
		Client:            c,
		logoutCallbackURL: logoutCallbackURL,
		request:           r,
	}, nil
}

func (in *logout) SingleLogoutURL(idToken string) string {
	endSessionEndpoint := in.config().Provider().EndSessionEndpointURL()
	v := endSessionEndpoint.Query()
	v.Add(openid.PostLogoutRedirectURI, in.logoutCallbackURL)

	if len(idToken) > 0 {
		v.Add(openid.IDTokenHint, idToken)
	}

	endSessionEndpoint.RawQuery = v.Encode()
	return endSessionEndpoint.String()
}
