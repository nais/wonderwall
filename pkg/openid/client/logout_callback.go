package client

import (
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/openid"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type LogoutCallback struct {
	*Client
	cookie    *openid.LogoutCookie
	validator urlpkg.Validator
	request   *http.Request
}

func NewLogoutCallback(c *Client, r *http.Request, cookie *openid.LogoutCookie, validator urlpkg.Validator) *LogoutCallback {
	return &LogoutCallback{
		Client:    c,
		cookie:    cookie,
		validator: validator,
		request:   r,
	}
}

func (in *LogoutCallback) PostLogoutRedirectURI() string {
	if in.cookie != nil && in.stateMismatchError() == nil && in.validator.IsValidRedirect(in.request, in.cookie.RedirectTo) {
		return in.cookie.RedirectTo
	}

	defaultRedirect := in.cfg.Client().PostLogoutRedirectURI()
	if defaultRedirect != "" {
		return defaultRedirect
	}

	ingress, err := urlpkg.MatchingIngress(in.request)
	if err != nil {
		return "/"
	}

	return ingress.String()
}

func (in *LogoutCallback) stateMismatchError() error {
	if in.cookie == nil {
		return fmt.Errorf("logout cookie is nil")
	}

	return openid.StateMismatchError(in.request.URL.Query(), in.cookie.State)
}
