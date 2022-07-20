package client

import (
	"net/http"
)

type LogoutCallback interface {
	PostLogoutRedirectURI() string
}

type logoutCallback struct {
	Client
	request *http.Request
	ingress string
}

func NewLogoutCallback(c Client, r *http.Request, ingress string) LogoutCallback {
	return &logoutCallback{
		Client:  c,
		request: r,
		ingress: ingress,
	}
}

func (in *logoutCallback) PostLogoutRedirectURI() string {
	redirect := in.config().Client().PostLogoutRedirectURI()

	if len(redirect) == 0 {
		return in.ingress
	}

	return redirect
}
