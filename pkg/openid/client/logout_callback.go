package client

import (
	"net/http"

	mw "github.com/nais/wonderwall/pkg/middleware"
)

type LogoutCallback interface {
	PostLogoutRedirectURI() string
}

type logoutCallback struct {
	Client
	request *http.Request
}

func NewLogoutCallback(c Client, r *http.Request) LogoutCallback {
	return &logoutCallback{
		Client:  c,
		request: r,
	}
}

func (in *logoutCallback) PostLogoutRedirectURI() string {
	redirect := in.config().Client().PostLogoutRedirectURI()

	if len(redirect) > 0 {
		return redirect
	}

	ingress, ok := mw.IngressFrom(in.request.Context())
	if !ok {
		return "/"
	}

	return ingress.String()
}
