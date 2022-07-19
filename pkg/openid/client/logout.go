package client

import (
	"fmt"
	"net/url"
)

type Logout interface {
	SingleLogoutURL(idToken string) string
}

type logout struct {
	Client
	endSessionEndpoint *url.URL
}

func NewLogout(c Client) (Logout, error) {
	endSessionEndpoint, err := url.Parse(c.config().Provider().EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing end session endpoint: %w", err)
	}

	return &logout{
		Client:             c,
		endSessionEndpoint: endSessionEndpoint,
	}, nil
}

func (in *logout) SingleLogoutURL(idToken string) string {
	v := in.endSessionEndpoint.Query()
	v.Add("post_logout_redirect_uri", in.config().Client().GetLogoutCallbackURI())

	if len(idToken) > 0 {
		v.Add("id_token_hint", idToken)
	}

	in.endSessionEndpoint.RawQuery = v.Encode()
	return in.endSessionEndpoint.String()
}
