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
}

func NewLogoutCallback(c Client, r *http.Request) LogoutCallback {
	return &logoutCallback{
		Client:  c,
		request: r,
	}
}

func (in *logoutCallback) PostLogoutRedirectURI() string {
	redirect := in.config().Client().GetPostLogoutRedirectURI()

	if len(redirect) == 0 {
		return in.config().Wonderwall().Ingress
	}

	return redirect
}
