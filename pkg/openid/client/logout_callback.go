package client

import (
	"net/http"

	mw "github.com/nais/wonderwall/pkg/middleware"
)

type LogoutCallback struct {
	*Client
	request *http.Request
}

func NewLogoutCallback(c *Client, r *http.Request) *LogoutCallback {
	return &LogoutCallback{
		Client:  c,
		request: r,
	}
}

func (in *LogoutCallback) PostLogoutRedirectURI() string {
	redirect := in.cfg.Client().PostLogoutRedirectURI()

	if len(redirect) > 0 {
		return redirect
	}

	ingress, ok := mw.IngressFrom(in.request.Context())
	if !ok {
		return "/"
	}

	return ingress.String()
}
